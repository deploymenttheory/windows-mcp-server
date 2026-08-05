// Command azurelab builds and tears down the Azure Blob Storage scaffolding used
// to validate evidence export against a real destination.
//
// It is an operator's provisioning tool, run on the host, and it is deliberately
// NOT part of the server's module — see scripts/azurelab/go.mod. Two reasons:
// the server ships no cloud SDK in this revision and `go mod tidy -diff` must
// stay clean, and nothing here should ever be reachable from the agent-driven
// desktop.
//
// That separation is also why this uses DefaultAzureCredential while the server
// refuses to. The rule the server follows — no ambient credential chain — is
// about a process an untrusted model can drive: the chain reads the vendors' bare
// environment names, which are not withheld from child processes, and it reaches
// IMDS. Neither applies to a tool an operator runs by hand from their own shell,
// authenticated by `az login`.
//
// The SAS it mints for the guest is deliberately **create-only**: no read, no
// delete, no list. That is the posture docs/evidence-export.md describes — the
// device can write its evidence and can neither read back nor destroy what is
// already there — and it is what makes the create-only refusal observable. The
// read side (list, download, verify) runs here on the host under the account key,
// which is the auditor's privilege, not the device's.
//
// Usage:
//
//	go run . -action create   -subscription <id> -resource-group <rg> -account <name> [-location uksouth] [-container evidence]
//	go run . -action sas      -subscription <id> -resource-group <rg> -account <name> -session 20260805-120000 [-ttl 4h]
//	go run . -action list     -subscription <id> -resource-group <rg> -account <name>
//	go run . -action download -subscription <id> -resource-group <rg> -account <name> -blob <name> -out <path>
//	go run . -action destroy  -subscription <id> -resource-group <rg>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
)

// The three artifacts an exported session produces. The order matters only for
// readability; the server ships the bundle first either way.
var artifactSuffixes = []string{".evidence.zip", ".manifest.json", ".manifest.sig"}

// exportEnvFor maps an artifact suffix to the environment variable the server
// reads its URL from. Kept here rather than imported so this module stays
// independent of the server's.
var exportEnvFor = map[string]string{
	".evidence.zip":  "WINDOWS_MCP_EXPORT_SIGNED_URL",
	".manifest.json": "WINDOWS_MCP_EXPORT_SIGNED_URL_MANIFEST",
	".manifest.sig":  "WINDOWS_MCP_EXPORT_SIGNED_URL_SIGNATURE",
}

// accountNameRe is Azure's own constraint on a storage account name. Checked here
// so a bad name fails immediately rather than after the resource group exists.
var accountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

type options struct {
	action       string
	subscription string
	resourceGrp  string
	location     string
	account      string
	container    string
	session      string
	blob         string
	out          string
	ttl          time.Duration
	yes          bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "azurelab: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var o options
	flag.StringVar(&o.action, "action", "", "create | sas | list | download | destroy")
	flag.StringVar(&o.subscription, "subscription", os.Getenv("AZURE_SUBSCRIPTION_ID"), "Azure subscription id")
	flag.StringVar(&o.resourceGrp, "resource-group", "rg-windows-mcp-evidence-lab", "resource group")
	flag.StringVar(&o.location, "location", "uksouth", "Azure region")
	flag.StringVar(&o.account, "account", "", "storage account name (3-24 lowercase alphanumerics)")
	flag.StringVar(&o.container, "container", "evidence", "blob container")
	flag.StringVar(&o.session, "session", "", "session stamp, e.g. 20260805-120000 (sas)")
	flag.StringVar(&o.blob, "blob", "", "blob name (download)")
	flag.StringVar(&o.out, "out", "", "local path to write to (download)")
	flag.DurationVar(&o.ttl, "ttl", 4*time.Hour, "SAS lifetime")
	flag.BoolVar(&o.yes, "yes", false, "skip the confirmation prompt (destroy)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("azure credentials (is `az login` done?): %w", err)
	}

	switch o.action {
	case "create":
		return createLab(ctx, cred, o)
	case "sas":
		return mintSAS(ctx, cred, o)
	case "list":
		return listBlobs(ctx, cred, o)
	case "download":
		return downloadBlob(ctx, cred, o)
	case "destroy":
		return destroyLab(ctx, cred, o)
	case "":
		flag.Usage()
		return errors.New("-action is required")
	default:
		return fmt.Errorf("unknown -action %q (want create, sas, list, download or destroy)", o.action)
	}
}

// createLab builds the resource group, storage account and container. It is
// idempotent: every call is a create-or-update, so re-running after a partial
// failure completes the scaffolding rather than colliding with it.
func createLab(ctx context.Context, cred *azidentity.DefaultAzureCredential, o options) error {
	if err := o.requireSubscription(); err != nil {
		return err
	}
	if !accountNameRe.MatchString(o.account) {
		return fmt.Errorf("-account %q must be 3-24 lowercase letters and digits", o.account)
	}

	rgClient, err := armresources.NewResourceGroupsClient(o.subscription, cred, nil)
	if err != nil {
		return fmt.Errorf("resource groups client: %w", err)
	}
	fmt.Printf("resource group %s (%s)...\n", o.resourceGrp, o.location)
	if _, err := rgClient.CreateOrUpdate(ctx, o.resourceGrp,
		armresources.ResourceGroup{Location: to.Ptr(o.location)}, nil); err != nil {
		return fmt.Errorf("create resource group: %w", err)
	}

	factory, err := armstorage.NewClientFactory(o.subscription, cred, nil)
	if err != nil {
		return fmt.Errorf("storage client factory: %w", err)
	}

	// TLS 1.2 minimum, HTTPS only, and public blob access off. The last is what
	// keeps "unauthenticated destination" meaning "the credential is in the URL"
	// rather than "anyone can read the evidence".
	fmt.Printf("storage account %s...\n", o.account)
	poller, err := factory.NewAccountsClient().BeginCreate(ctx, o.resourceGrp, o.account,
		armstorage.AccountCreateParameters{
			Kind:     to.Ptr(armstorage.KindStorageV2),
			SKU:      &armstorage.SKU{Name: to.Ptr(armstorage.SKUNameStandardLRS)},
			Location: to.Ptr(o.location),
			Properties: &armstorage.AccountPropertiesCreateParameters{
				AllowBlobPublicAccess:  to.Ptr(false),
				EnableHTTPSTrafficOnly: to.Ptr(true),
				MinimumTLSVersion:      to.Ptr(armstorage.MinimumTLSVersionTLS12),
				AllowSharedKeyAccess:   to.Ptr(true), // the SAS is signed with it
			},
		}, nil)
	if err != nil {
		return fmt.Errorf("begin create storage account: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("create storage account: %w", err)
	}

	fmt.Printf("container %s...\n", o.container)
	_, err = factory.NewBlobContainersClient().Create(ctx, o.resourceGrp, o.account, o.container,
		armstorage.BlobContainer{
			ContainerProperties: &armstorage.ContainerProperties{
				PublicAccess: to.Ptr(armstorage.PublicAccessNone),
			},
		}, nil)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	fmt.Printf("\nready: https://%s.blob.core.windows.net/%s\n", o.account, o.container)
	fmt.Printf("next:  go run . -action sas -subscription %s -resource-group %s -account %s -session <stamp>\n",
		o.subscription, o.resourceGrp, o.account)
	return nil
}

// mintSAS prints the three create-only blob SAS URLs for one session, as
// PowerShell assignments ready to paste into the guest.
//
// One URL per artifact because a SAS signature covers a single blob name — the
// same constraint the server documents for every signed-URL destination.
func mintSAS(ctx context.Context, cred *azidentity.DefaultAzureCredential, o options) error {
	if err := o.requireSubscription(); err != nil {
		return err
	}
	if o.session == "" {
		return errors.New("-session is required, e.g. -session 20260805-120000")
	}

	shared, err := sharedKey(ctx, cred, o)
	if err != nil {
		return err
	}

	// Create and Write, and nothing else. Read would let the device pull back
	// another session's evidence; Delete would let it destroy the record it just
	// wrote, which is the whole thing this export exists to prevent.
	perms := sas.BlobPermissions{Create: true, Write: true}
	// Ten minutes of backdating absorbs clock skew between this host and the guest;
	// without it a freshly minted SAS can be rejected as not-yet-valid.
	start := time.Now().UTC().Add(-10 * time.Minute)
	expiry := time.Now().UTC().Add(o.ttl)

	fmt.Printf("# create-only SAS for session %s, valid until %s\n",
		o.session, expiry.Format(time.RFC3339))
	for _, suffix := range artifactSuffixes {
		name := "session-" + o.session + suffix
		values := sas.BlobSignatureValues{
			Protocol:      sas.ProtocolHTTPS, // https-only, enforced by the service
			StartTime:     start,
			ExpiryTime:    expiry,
			Permissions:   perms.String(),
			ContainerName: o.container,
			BlobName:      name,
		}
		q, sErr := values.SignWithSharedKey(shared)
		if sErr != nil {
			return fmt.Errorf("sign SAS for %s: %w", name, sErr)
		}
		url := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s",
			o.account, o.container, name, q.Encode())
		fmt.Printf("$env:%s = '%s'\n", exportEnvFor[suffix], url)
	}
	return nil
}

// listBlobs shows what actually landed. It runs under the account key, not the
// SAS: the device is not permitted to list, and that asymmetry is the point.
func listBlobs(ctx context.Context, cred *azidentity.DefaultAzureCredential, o options) error {
	client, err := blobClient(ctx, cred, o)
	if err != nil {
		return err
	}
	pager := client.NewListBlobsFlatPager(o.container, nil)
	found := 0
	for pager.More() {
		page, pErr := pager.NextPage(ctx)
		if pErr != nil {
			return fmt.Errorf("list blobs: %w", pErr)
		}
		for _, b := range page.Segment.BlobItems {
			found++
			size := int64(0)
			if b.Properties != nil && b.Properties.ContentLength != nil {
				size = *b.Properties.ContentLength
			}
			fmt.Printf("%-48s %10d bytes  %s\n", *b.Name, size, blobMetadata(b.Metadata))
		}
	}
	if found == 0 {
		fmt.Println("(container is empty)")
	}
	return nil
}

// blobMetadata renders the metadata the server attaches, so a reviewer can see
// the session and audit head without downloading the object.
func blobMetadata(m map[string]*string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for _, k := range []string{"session", "audit_head", "sha256", "signed"} {
		if v, ok := m[k]; ok && v != nil {
			parts = append(parts, k+"="+*v)
		}
	}
	return strings.Join(parts, " ")
}

// downloadBlob fetches one object so the bundle can be verified after its round
// trip through blob storage — the check that matters most, since a bundle that no
// longer verifies is not evidence.
func downloadBlob(ctx context.Context, cred *azidentity.DefaultAzureCredential, o options) error {
	if o.blob == "" || o.out == "" {
		return errors.New("-blob and -out are both required for download")
	}
	client, err := blobClient(ctx, cred, o)
	if err != nil {
		return err
	}
	f, err := os.Create(o.out)
	if err != nil {
		return fmt.Errorf("create %s: %w", o.out, err)
	}
	defer func() { _ = f.Close() }()

	n, err := client.DownloadFile(ctx, o.container, o.blob, f, nil)
	if err != nil {
		return fmt.Errorf("download %s: %w", o.blob, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", o.out, n)
	return nil
}

// destroyLab removes the whole resource group. It prompts unless -yes is given:
// the group name is a flag with a default, and deleting the wrong one is not
// recoverable.
func destroyLab(ctx context.Context, cred *azidentity.DefaultAzureCredential, o options) error {
	if err := o.requireSubscription(); err != nil {
		return err
	}
	if !o.yes {
		fmt.Printf("delete resource group %q in subscription %s, and everything in it? [y/N] ",
			o.resourceGrp, o.subscription)
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return errors.New("cancelled")
		}
	}

	rgClient, err := armresources.NewResourceGroupsClient(o.subscription, cred, nil)
	if err != nil {
		return fmt.Errorf("resource groups client: %w", err)
	}
	poller, err := rgClient.BeginDelete(ctx, o.resourceGrp, nil)
	if err != nil {
		return fmt.Errorf("begin delete resource group: %w", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("delete resource group: %w", err)
	}
	fmt.Printf("deleted %s\n", o.resourceGrp)
	return nil
}

// sharedKey fetches the account's first access key, which is what a SAS is signed
// with. It never prints it.
func sharedKey(
	ctx context.Context,
	cred *azidentity.DefaultAzureCredential,
	o options,
) (*azblob.SharedKeyCredential, error) {
	factory, err := armstorage.NewClientFactory(o.subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("storage client factory: %w", err)
	}
	keys, err := factory.NewAccountsClient().ListKeys(ctx, o.resourceGrp, o.account, nil)
	if err != nil {
		return nil, fmt.Errorf("list account keys: %w", err)
	}
	if len(keys.Keys) == 0 || keys.Keys[0].Value == nil {
		return nil, errors.New("storage account returned no access keys")
	}
	shared, err := azblob.NewSharedKeyCredential(o.account, *keys.Keys[0].Value)
	if err != nil {
		return nil, fmt.Errorf("shared key credential: %w", err)
	}
	return shared, nil
}

func blobClient(
	ctx context.Context,
	cred *azidentity.DefaultAzureCredential,
	o options,
) (*azblob.Client, error) {
	if err := o.requireSubscription(); err != nil {
		return nil, err
	}
	shared, err := sharedKey(ctx, cred, o)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s.blob.core.windows.net/", o.account)
	client, err := azblob.NewClientWithSharedKeyCredential(url, shared, nil)
	if err != nil {
		return nil, fmt.Errorf("blob client: %w", err)
	}
	return client, nil
}

func (o options) requireSubscription() error {
	if o.subscription == "" {
		return errors.New("-subscription is required (or set AZURE_SUBSCRIPTION_ID)")
	}
	if o.account == "" && o.action != "destroy" {
		return errors.New("-account is required")
	}
	return nil
}
