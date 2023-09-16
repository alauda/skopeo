package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/containers/image/v5/internal/imagedestination/impl"
	"github.com/containers/image/v5/internal/imagedestination/stubs"
	"github.com/containers/image/v5/internal/private"
	"github.com/containers/image/v5/internal/putblobdigest"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type ociImageDestination struct {
	impl.Compat
	impl.PropertyMethodsInitialize
	stubs.NoPutBlobPartialInitialize
	stubs.NoSignaturesInitialize

	ref     registryReference
	current digest.Digest
}

// newImageDestination returns an ImageDestination for writing to an existing directory.
func newImageDestination(sys *types.SystemContext, ref registryReference) (private.ImageDestination, error) {
	desiredLayerCompression := types.Compress
	if sys != nil && sys.OCIAcceptUncompressedLayers {
		desiredLayerCompression = types.PreserveOriginal
	}

	d := &ociImageDestination{
		PropertyMethodsInitialize: impl.PropertyMethods(impl.Properties{
			SupportedManifestMIMETypes: []string{
				imgspecv1.MediaTypeImageManifest,
				imgspecv1.MediaTypeImageIndex,
			},
			DesiredLayerCompression:        desiredLayerCompression,
			AcceptsForeignLayerURLs:        true,
			MustMatchRuntimeOS:             false,
			IgnoresEmbeddedDockerReference: false, // N/A, DockerReference() returns nil.
			HasThreadSafePutBlob:           true,
		}),
		NoPutBlobPartialInitialize: stubs.NoPutBlobPartial(ref),
		NoSignaturesInitialize:     stubs.NoSignatures("Pushing signatures for OCI images is not supported"),

		ref: ref,
	}
	d.Compat = impl.AddCompat(d)

	if err := ensureDirectoryExists(d.ref.dir); err != nil {
		return nil, err
	}
	return d, nil
}

// Reference returns the reference used to set up this destination.  Note that this should directly correspond to user's intent,
// e.g. it should use the public hostname instead of the result of resolving CNAMEs or following redirects.
func (d *ociImageDestination) Reference() types.ImageReference {
	return d.ref
}

// Close removes resources associated with an initialized ImageDestination, if any.
func (d *ociImageDestination) Close() error {
	return nil
}

// PutBlobWithOptions writes contents of stream and returns data representing the result.
// inputInfo.Digest can be optionally provided if known; if provided, and stream is read to the end without error, the digest MUST match the stream contents.
// inputInfo.Size is the expected length of stream, if known.
// inputInfo.MediaType describes the blob format, if known.
// WARNING: The contents of stream are being verified on the fly.  Until stream.Read() returns io.EOF, the contents of the data SHOULD NOT be available
// to any other readers for download using the supplied digest.
// If stream.Read() at any time, ESPECIALLY at end of input, returns an error, PutBlobWithOptions MUST 1) fail, and 2) delete any data stored so far.
func (d *ociImageDestination) PutBlobWithOptions(ctx context.Context, stream io.Reader, inputInfo types.BlobInfo, options private.PutBlobOptions) (private.UploadedBlob, error) {
	blobFile, err := os.CreateTemp(d.ref.dir, "registry-put-blob")
	if err != nil {
		return private.UploadedBlob{}, err
	}
	succeeded := false
	explicitClosed := false
	defer func() {
		if !explicitClosed {
			blobFile.Close()
		}
		if !succeeded {
			os.Remove(blobFile.Name())
		}
	}()

	digester, stream := putblobdigest.DigestIfCanonicalUnknown(stream, inputInfo)
	// TODO: This can take quite some time, and should ideally be cancellable using ctx.Done().
	size, err := io.Copy(blobFile, stream)
	if err != nil {
		return private.UploadedBlob{}, err
	}
	blobDigest := digester.Digest()
	if inputInfo.Size != -1 && size != inputInfo.Size {
		return private.UploadedBlob{}, fmt.Errorf("Size mismatch when copying %s, expected %d, got %d", blobDigest, inputInfo.Size, size)
	}
	if err := blobFile.Sync(); err != nil {
		return private.UploadedBlob{}, err
	}

	// On POSIX systems, blobFile was created with mode 0600, so we need to make it readable.
	// On Windows, the “permissions of newly created files” argument to syscall.Open is
	// ignored and the file is already readable; besides, blobFile.Chmod, i.e. syscall.Fchmod,
	// always fails on Windows.
	if runtime.GOOS != "windows" {
		if err := blobFile.Chmod(0644); err != nil {
			return private.UploadedBlob{}, err
		}
	}

	blobPath := d.ref.blobPath(blobDigest)
	if err := ensureParentDirectoryExists(blobPath); err != nil {
		return private.UploadedBlob{}, err
	}

	// need to explicitly close the file, since a rename won't otherwise not work on Windows
	blobFile.Close()
	explicitClosed = true
	if err := os.Rename(blobFile.Name(), blobPath); err != nil {
		return private.UploadedBlob{}, err
	}
	succeeded = true
	return private.UploadedBlob{Digest: blobDigest, Size: size}, nil
}

// TryReusingBlobWithOptions checks whether the transport already contains, or can efficiently reuse, a blob, and if so, applies it to the current destination
// (e.g. if the blob is a filesystem layer, this signifies that the changes it describes need to be applied again when composing a filesystem tree).
// info.Digest must not be empty.
// If the blob has been successfully reused, returns (true, info, nil).
// If the transport can not reuse the requested blob, TryReusingBlob returns (false, {}, nil); it returns a non-nil error only on an unexpected failure.
func (d *ociImageDestination) TryReusingBlobWithOptions(ctx context.Context, info types.BlobInfo, options private.TryReusingBlobOptions) (bool, private.ReusedBlob, error) {
	if info.Digest == "" {
		return false, private.ReusedBlob{}, errors.New("Can not check for a blob with unknown digest")
	}

	blobPath := d.ref.blobPath(info.Digest)
	finfo, err := os.Stat(blobPath)
	if err != nil && os.IsNotExist(err) {
		return false, private.ReusedBlob{}, nil
	}
	if err != nil {
		return false, private.ReusedBlob{}, err
	}

	return true, private.ReusedBlob{Digest: info.Digest, Size: finfo.Size()}, nil
}

// PutManifest writes a manifest to the destination.  Per our list of supported manifest MIME types,
// this should be either an OCI manifest (possibly converted to this format by the caller) or index,
// neither of which we'll need to modify further.
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to overwrite the manifest for (when
// the primary manifest is a manifest list); this should always be nil if the primary manifest is not a manifest list.
// It is expected but not enforced that the instanceDigest, when specified, matches the digest of `manifest` as generated
// by `manifest.Digest()`.
// FIXME? This should also receive a MIME type if known, to differentiate between schema versions.
// If the destination is in principle available, refuses this manifest type (e.g. it does not recognize the schema),
// but may accept a different manifest type, the returned error must be an ManifestTypeRejectedError.
func (d *ociImageDestination) PutManifest(ctx context.Context, m []byte, instanceDigest *digest.Digest) error {
	var targetDigest digest.Digest
	var err error
	if instanceDigest != nil {
		targetDigest = *instanceDigest
	} else {
		targetDigest, err = manifest.Digest(m)
		if err != nil {
			return err
		}
	}

	blobPath := d.ref.blobPath(targetDigest)
	if err := ensureParentDirectoryExists(blobPath); err != nil {
		return err
	}
	if err := os.WriteFile(blobPath, m, 0644); err != nil {
		return err
	}

	mt := manifest.GuessMIMEType(m)

	links := map[string]digest.Digest{
		d.ref.revisionLinkPath(targetDigest): targetDigest,
	}

	if mt != manifest.DockerV2ListMediaType && mt != imgspecv1.MediaTypeImageIndex {
		man, err := manifest.FromBlob(m, mt)
		if err != nil {
			return nil
		}
		links[d.ref.layerLinkPath(man.ConfigInfo().Digest)] = man.ConfigInfo().Digest
		for _, layer := range man.LayerInfos() {
			links[d.ref.layerLinkPath(layer.Digest)] = layer.Digest
		}
	}

	if err := ensureLinks(links); err != nil {
		return err
	}

	d.current = targetDigest
	return nil
}

// Commit marks the process of storing the image as successful and asks for the image to be persisted.
// unparsedToplevel contains data about the top-level manifest of the source (which may be a single-arch image or a manifest list
// if PutManifest was only called for the single-arch image with instanceDigest == nil), primarily to allow lookups by the
// original manifest list digest, if desired.
// WARNING: This does not have any transactional semantics:
// - Uploaded data MAY be visible to others before Commit() is called
// - Uploaded data MAY be removed or MAY remain around if Close() is called without Commit() (i.e. rollback is allowed but not guaranteed)
func (d *ociImageDestination) Commit(ctx context.Context, image types.UnparsedImage) error {
	if d.current == "" {
		return fmt.Errorf("no manifest")
	}
	links := map[string]digest.Digest{
		d.ref.tagIndexLinkPath(d.current): d.current,
		d.ref.tagCurrentLinkPath():        d.current,
	}
	if err := ensureLinks(links); err != nil {
		return err
	}
	return nil
}

func ensureDirectoryExists(path string) error {
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	return nil
}

// ensureParentDirectoryExists ensures the parent of the supplied path exists.
func ensureParentDirectoryExists(path string) error {
	return ensureDirectoryExists(filepath.Dir(path))
}

func ensureLinks(links map[string]digest.Digest) error {
	for path, content := range links {
		if err := ensureParentDirectoryExists(path); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}
	return nil
}
