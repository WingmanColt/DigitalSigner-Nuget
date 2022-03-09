1. Installation guide
- Download OnlineDocumentSigner.DocumentSigner.1.0.0.nupkg from https://github.com/WingmanColt/DigitalSigner

2. Setup a service for digital sign in Startup.cs / Program.cs for newer versions.
- builder.Services.AddTransient<ISignService, SignService>();

3. Registering service in controller and using.

    public interface ISignService
    {
	// Opens personal certificates store
        int SignDocumentByUpload(string loadPath, string savePath, string certPath, string Password, StoreName store, StoreLocation location);

	// Sign with specified .pfx file in local storage
        int SignDocumentStored(string loadPath, string savePath, StoreName store, StoreLocation location);
    }


Example #1:

_SignService.SignDocumentStored("{Document path to sign}, {Full dir to save new one}, {which store to use}, {Location of store}")

Example #2:
																               // where to save specified file
_SignService.SignDocumentByUpload("{Document path to sign}, {Full dir to save new one}, {certificae full path}, {Password for specified cert}, {Store name}, {Location of store}")


    //
    // Summary:
    //     Specifies the name of the X.509 certificate store to open.
    public enum StoreName
    {
        //
        // Summary:
        //     The X.509 certificate store for other users.
        AddressBook = 1,
        //
        // Summary:
        //     The X.509 certificate store for third-party certificate authorities (CAs).
        AuthRoot,
        //
        // Summary:
        //     The X.509 certificate store for intermediate certificate authorities (CAs).
        CertificateAuthority,
        //
        // Summary:
        //     The X.509 certificate store for revoked certificates.
        Disallowed,
        //
        // Summary:
        //     The X.509 certificate store for personal certificates.
        My,
        //
        // Summary:
        //     The X.509 certificate store for trusted root certificate authorities (CAs).
        Root,
        //
        // Summary:
        //     The X.509 certificate store for directly trusted people and resources.
        TrustedPeople,
        //
        // Summary:
        //     The X.509 certificate store for directly trusted publishers.
        TrustedPublisher
    }


    public enum StoreLocation
    {
        //
        // Summary:
        //     The X.509 certificate store used by the current user.
        CurrentUser = 1,
        //
        // Summary:
        //     The X.509 certificate store assigned to the local machine.
        LocalMachine
    }