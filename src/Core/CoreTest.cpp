#include <Testing.h>

#include "VolumeCreator.h"
#include "Unix/CoreService.h"
#include "RandomNumberGenerator.h"
#include "CoreException.h"

#include "Volume/EncryptionThreadPool.h"
#include "Platform/SerializerFactory.h"
#include "Platform/Functor.h"
#include "Platform/FileStream.h"
#include "Common/SecurityToken.h"
#include "Common/MockSecurityToken.h"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <optional>

using namespace VeraCrypt;
using namespace std;

#define DEFAULT_PASSWORD "12345"
#define PASSWORD_TO_CHANGE_TO "54321"
#define DEFAULT_REDKEY_DATA_SIZE (128 + 128/2)
#define TOKEN_KEY L"test token key"


#define KB(k) (k*1024)
#define MB(m) (KB(m)*1024)


static Buffer *redkeyBuffer;


struct VolumeTestParams {
    string caseName;
    shared_ptr<MountOptions> opts;
    shared_ptr<VolumeCreationOptions> createOpts;
    bool useBluekey;
};

template ParameterizedFunctionalTest<VolumeTestParams>::ParameterizedFunctionalTest(string name, paramTestFunc<VolumeTestParams> func, VolumeTestParams *param);

class AdminPasswordRequestHandler : public GetStringFunctor
{
    public:
    virtual void operator() (string &str)
    {
        throw ElevationFailed (SRC_POS, "sudo", 1, "");
    }
};

FilesystemPath TestFile(string name) {
    struct stat fstat;

    auto found = false;
    while (!found) {
        if (stat ("Tests", &fstat) == 0) {
            auto *wd = getcwd(NULL, 0);
            return FilesystemPath(string(wd)).Append(L"Tests").Append(StringConverter::ToWide(name));
        }
        chdir("..");
    }
}

void SetUp() {
    SerializerFactory::Initialize();

    SecurityToken::UseImpl(shared_ptr<SecurityTokenIface>(new MockSecurityTokenImpl()));

    VeraCrypt::CoreService::Start();

    RandomNumberGenerator::Start();

    // this is from UserInterface.cpp
    // LangString.Init();
    VeraCrypt::Core->Init();
    VeraCrypt::Core->SetAdminPasswordCallback (shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler));
}

void TearDown() {
    RandomNumberGenerator::Stop();
    CoreService::Stop();
    SerializerFactory::Deinitialize();
}


shared_ptr<VolumePassword> GetPassword(string passwordString) {
    size_t ulen = passwordString.length();
    return shared_ptr<VolumePassword>(new VolumePassword ((uint8*)passwordString.c_str(), ulen));
}


shared_ptr<MountOptions> GetOptions(string name) {
    shared_ptr<VolumePath> volumePath(new VolumePath(TestFile(name + ".vol")));
    shared_ptr<VolumePassword> password = GetPassword(DEFAULT_PASSWORD);
    

    Sha512 *SelectedHash = new Sha512();
    shared_ptr<Pkcs5Kdf> kdf = Pkcs5Kdf::GetAlgorithm (*SelectedHash);
    shared_ptr<KeyfileList> keyfiles(new KeyfileList());
    VolumeProtection::Enum protection = VolumeProtection::None;
    shared_ptr<VolumePassword> protectionPassword;
    shared_ptr<Pkcs5Kdf> protectionKdf;
    shared_ptr<KeyfileList> protectionKeyfileList(new KeyfileList());
    VolumeType::Enum volumeType = VolumeType::Unknown;
    wstring securityTokenKeySpec;


    MountOptions opts;
    opts.Path = volumePath;
    opts.FilesystemOptions = wstring();
    opts.FilesystemType = wstring();
    opts.NoFilesystem = false;
    opts.Password = password;
    opts.Kdf = kdf;
    opts.Keyfiles = keyfiles;
    opts.Protection = protection;
    opts.ProtectionPassword = protectionPassword;
    opts.ProtectionKdf = protectionKdf;
    opts.ProtectionKeyfiles = protectionKeyfileList;
    opts.SecurityTokenKeySpec = securityTokenKeySpec;

    opts.SlotNumber = 0;

    shared_ptr<MountOptions> result = shared_ptr<MountOptions>(new MountOptions());
    *result = opts;
    return result;
}


shared_ptr<VolumeCreationOptions> GetCreateOpts(string name) {
    MountOptions mopts = *GetOptions(name);

    VolumeCreationOptions opts;
    
    opts.FilesystemClusterSize = 0; // default
    opts.SectorSize = 512;
    // XXX: other filesystems doesn't work, because we can only format fat fs within Core
    opts.Filesystem = VolumeCreationOptions::FilesystemType::Enum::FAT;
    opts.EA = shared_ptr <AESTwofishSerpent> (new AESTwofishSerpent ());
    opts.Quick = false;
    opts.Size = 10*1024*1024;
    opts.Type = VolumeType::Normal;

    opts.Password = make_shared<VolumePassword>(*(mopts.Password));
    opts.Pim = mopts.Pim;
    opts.Keyfiles = mopts.Keyfiles;
    opts.SecurityTokenKeySpec = mopts.SecurityTokenKeySpec;
    opts.Path = *mopts.Path;
    
    opts.VolumeHeaderKdf = mopts.Kdf;

    shared_ptr<VolumeCreationOptions> result = shared_ptr<VolumeCreationOptions>(new VolumeCreationOptions());
    *result = opts;
    return result;

}


Test* WithParams(string name, paramTestFunc<VolumeTestParams> f, shared_ptr<VolumeCreationOptions> createOpts, shared_ptr<MountOptions> mountOpts) {
    VolumeTestParams *params = new VolumeTestParams{name, mountOpts, createOpts, false};
    return Testing::param<VolumeTestParams>(name, f, params);
}

Test* WithDefaultParams(string name, paramTestFunc<VolumeTestParams> f) {
    auto createOpts = GetCreateOpts(name);
    auto mountOpts = GetOptions(name);
    return WithParams(name, f, createOpts, mountOpts);
}



void WithBluekey(const VolumeTestParams *params, shared_ptr<Keyfile> kf) {
    // setting this signals to use security token key
    params->opts->SecurityTokenKeySpec = params->createOpts->SecurityTokenKeySpec = TOKEN_KEY;
    params->createOpts->Keyfiles->push_back(kf);
    params->opts->Keyfiles->push_back(kf);
}




shared_ptr<Keyfile> CreateKeyfile(string name) {
    SecureBuffer data(100);
    RandomNumberGenerator::GetData(data);

    FilePath kfp(TestFile(name));
    File f;
    f.Open(kfp, File::FileOpenMode::CreateWrite);
    f.Write(data);
    f.Close();

    auto keyfile = shared_ptr<Keyfile>(new Keyfile(kfp));
    return keyfile;
}



shared_ptr<Keyfile> CreateBluekey(size_t size) {   
    SecureBuffer buffer(size);
    RandomNumberGenerator::GetData(buffer, true);

    redkeyBuffer = new Buffer(ConstBufferPtr(buffer));

    File redkeyOriginal;
    redkeyOriginal.Open(TestFile("redkey_origin.key"), File::FileOpenMode::CreateWrite);
    redkeyOriginal.Write(*redkeyBuffer);
    redkeyOriginal.Close();

    FilePath bluekeyPath(TestFile("bluekey.key"));
    Keyfile::CreateBluekey(bluekeyPath, TOKEN_KEY, buffer);
    return shared_ptr<Keyfile>(new Keyfile(bluekeyPath));
}

shared_ptr<Keyfile> CreateBluekey() {
    return CreateBluekey(DEFAULT_REDKEY_DATA_SIZE);
}



VolumeTestParams *GetTestParams(void *arg) {
    VolumeTestParams *params = (VolumeTestParams*) arg;
    return params;
}




void EnsureBluekey(const VolumeTestParams *params, size_t keyfileSize) {
    shared_ptr<Keyfile> kf = CreateBluekey(keyfileSize);
    WithBluekey(params, kf);
}

void EnsureBluekey(const VolumeTestParams *params) {
    EnsureBluekey(params, DEFAULT_REDKEY_DATA_SIZE);
}

void CreateVolume(shared_ptr<TestResult> r, VolumeTestParams *params) {
    VolumeCreator creator;
    shared_ptr<VolumeCreationOptions> opts = params->createOpts;

    if (!opts->EA) {
        r->Failed("encryption algorithm is null for creation");
        return;
    }
    creator.CreateVolume(opts);

    while (creator.GetProgressInfo().CreationInProgress) {
        Thread::Sleep(1000);
    }
    creator.CheckResult();
    r->Phase("volume created successfully");
}

void Read(char *buf, shared_ptr<Volume> v, size_t offset, size_t size);

void DumpVolume() {
    MountOptions opts = *GetOptions(TestFile("dump.vol"));

    try {
        shared_ptr<Volume> vol = VeraCrypt::Core->OpenVolume(opts.Path,
            true, opts.Password, 0, opts.Kdf,
            opts.Keyfiles, opts.SecurityTokenKeySpec, false,
            opts.Protection, opts.ProtectionPassword, 0, opts.ProtectionKdf, opts.ProtectionKeyfiles,
            opts.ProtectionSecurityTokenKeySpec,
            false, VolumeType::Unknown, false, false);

        if (vol) {
            trace_msg(vol->GetSize());
            trace_msg(vol->GetVolumeCreationTime());
            trace_msg(vol->GetFile()->IsOpen());
            trace_msg(string(vol->GetFile()->GetPath()));

            size_t rs = 256;
            char *buffer = new char[rs];
            Read(buffer, vol, 0, rs);

            string s((char*)buffer, rs);
            trace_msg("DATA" << s);
        } else {
            trace_msg("Volume is null");
        }
    } catch (exception &ex) {
        trace_msg("EX" << ex.what());
    }
}

void EnsureVolumeMounts(shared_ptr<TestResult> r, VolumeTestParams params) {   
    try {
        shared_ptr<VolumeInfo> vi = VeraCrypt::Core->MountVolume(*params.opts);
        if (vi) {
            VeraCrypt::Core->DismountVolume(vi);
        } else {
            r->Failed("no volume information available after mounting");
        }
    } catch (exception &e) {
        r->Failed(string("ex caught") + e.what());
    }
    
}


shared_ptr<Keyfile> RevealRedkey(VolumeTestParams *params) {
    shared_ptr<Keyfile> kf = params->opts->Keyfiles->front();


    FilePath redkeyPath(TestFile("redkey.key"));
    kf->RevealRedkey(redkeyPath, params->opts->SecurityTokenKeySpec);
    return shared_ptr<Keyfile>(new Keyfile(redkeyPath));
}


void Read(char *buf, shared_ptr<Volume> v, size_t offset, size_t size) {
    if ((uint64) offset + size > v->GetSize())
        size = v->GetSize() - offset;

    size_t sectorSize = v->GetSectorSize();
    if (size % sectorSize != 0 || offset % sectorSize != 0)
    {
        // Support for non-sector-aligned read operations is required by some loop device tools
        // which may analyze the volume image before attaching it as a device

        uint64 alignedOffset = offset - (offset % sectorSize);
        uint64 alignedSize = size + (offset % sectorSize);

        if (alignedSize % sectorSize != 0)
            alignedSize += sectorSize - (alignedSize % sectorSize);

        SecureBuffer alignedBuffer (alignedSize);

        // FuseService::ReadVolumeSectors (alignedBuffer, alignedOffset);
        v->ReadSectors(alignedBuffer, alignedOffset);
        BufferPtr ((uint8 *) buf, size).CopyFrom (alignedBuffer.GetRange (offset % sectorSize, size));
    }
    else
    {
        v->ReadSectors(BufferPtr ((uint8 *) buf, size), offset);
        // FuseService::ReadVolumeSectors (, offset);
    }
}


#define PHASE(msg) trace_msg(">>>>>> " << msg << "<<<<<<<<")


void ChangeSecurityParametersTest(shared_ptr<TestResult> r, VolumeTestParams *params,
    shared_ptr<VolumePassword> newPassword,
    int newPim, 
    shared_ptr<VeraCrypt::KeyfileList> newKeyfiles, 
    shared_ptr<wstring> newSecurityTokenKeySpec,
    shared_ptr<VeraCrypt::Pkcs5Kdf> newPkcs5Kdf
    ) {

    auto opts = params->opts;

    auto volumePath = opts->Path;
    bool preserveTimestamps = params->opts->PreserveTimestamps;
    bool truecryptMode = false;


    auto password = opts->Password;
    auto pim = opts->Pim;
    auto kdf = opts->Kdf;
    shared_ptr<VeraCrypt::KeyfileList> keyfiles = opts->Keyfiles;
    wstring securityTokenKeySpec = opts->SecurityTokenKeySpec;

    
    if (!newPkcs5Kdf) {
        newPkcs5Kdf = kdf;
    }

    // null value => same
    // empty list => drop kf
    // KEYFILES_TO_CHANGE_TO => replace kefiles
    shared_ptr<VeraCrypt::KeyfileList> greenKeyfiles = newKeyfiles;
    if (!greenKeyfiles) {
        r->Phase("keeping the same keyfiles");
        greenKeyfiles = keyfiles;
    }
    

    // null => same
    // empty => drop key
    // non-empty => use specified
    wstring greenSecurityTokenKeySpec;
    if (!newSecurityTokenKeySpec) {
        r->Phase("keeping the same tokenspec");
        greenSecurityTokenKeySpec = securityTokenKeySpec;
    } else {
        greenSecurityTokenKeySpec = *newSecurityTokenKeySpec;
    }

    auto greenPim = newPim;
    if (greenPim < 0) {
        r->Phase("keeping the same pim");
        greenPim = pim;
    }

    auto greenPassword = newPassword;
    if (!greenPassword) {
        r->Phase("keeping the same password");
        greenPassword = password;
    }
    
    int wipeCount = 3;
    

    r->Phase("applying security parameters changes");
    try {
        VeraCrypt::Core->ChangePassword(volumePath, preserveTimestamps,
        password, pim, kdf, keyfiles, securityTokenKeySpec,
        greenPassword, greenPim, greenKeyfiles, greenSecurityTokenKeySpec, false,
        newPkcs5Kdf, wipeCount);
    } catch (exception &e) {
        r->Failed("unable to change security parameters");
        return;
    }
    

    params->opts->Password = greenPassword;
    params->opts->Pim = greenPim;
    params->opts->Keyfiles = greenKeyfiles;
    params->opts->SecurityTokenKeySpec = greenSecurityTokenKeySpec;
    params->opts->Kdf = newPkcs5Kdf;

    r->Phase("mounting updated volume");
    EnsureVolumeMounts(r, *params);
}

void ChangePasswordTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("changings password");

    auto newPassword = GetPassword(PASSWORD_TO_CHANGE_TO);

    ChangeSecurityParametersTest(r, params, newPassword, -1,
        shared_ptr<VeraCrypt::KeyfileList>(nullptr),
        shared_ptr<wstring>(nullptr), shared_ptr<Pkcs5Kdf>(nullptr));

}

void AddKeyfileToVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);


    r->Phase("creating keyfile");
    shared_ptr<Keyfile> kf = CreateKeyfile("added_keyfile.key");

    r->Phase("creating kfl");
    shared_ptr<KeyfileList> kfl = shared_ptr<KeyfileList>(new KeyfileList());
    kfl->push_back(kf);

    r->Phase("adding keyfile to the volume");
    ChangeSecurityParametersTest(r, params, shared_ptr<VolumePassword>(nullptr),
        -1, shared_ptr<VeraCrypt::KeyfileList>(kfl),
    shared_ptr<wstring>(nullptr), shared_ptr<Pkcs5Kdf>(nullptr));
}

void AddBluekeyToVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);
    
    r->Phase("creating bluekey");
    shared_ptr<KeyfileList> kfl = shared_ptr<KeyfileList>(new KeyfileList());
    kfl->push_back(CreateBluekey());
        
    r->Phase("adding bluekey to the volume");
    ChangeSecurityParametersTest(r, params, shared_ptr<VolumePassword>(nullptr),
        -1, shared_ptr<VeraCrypt::KeyfileList>(kfl),
    shared_ptr<wstring>(new wstring(TOKEN_KEY)), shared_ptr<Pkcs5Kdf>(nullptr));
}

void RemoveBluekeyFromVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    EnsureBluekey(params);
    CreateVolume(r, params);
    
    shared_ptr<KeyfileList> kfl = shared_ptr<KeyfileList>(new KeyfileList());
        
    r->Phase("removing bluekey from the volume");
    ChangeSecurityParametersTest(r, params, shared_ptr<VolumePassword>(nullptr),
        -1, shared_ptr<VeraCrypt::KeyfileList>(kfl),
    shared_ptr<wstring>(new wstring(L"")), shared_ptr<Pkcs5Kdf>(nullptr));
}


void UseBluekeyAsRedkeyTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    EnsureBluekey(params);
    CreateVolume(r, params);
    
           
    r->Phase("removing bluekey from the volume");
    ChangeSecurityParametersTest(r, params,
        shared_ptr<VolumePassword>(nullptr),
        -1,
        shared_ptr<VeraCrypt::KeyfileList>(nullptr),
        shared_ptr<wstring>(new wstring(L"")),
        shared_ptr<Pkcs5Kdf>(nullptr));
}


void UseTokenKeyWithoutKeyfilesTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    EnsureBluekey(params);
    CreateVolume(r, params);
    

    shared_ptr<KeyfileList> kfl = shared_ptr<KeyfileList>(new KeyfileList());

    r->Phase("removing bluekey from the volume");
    ChangeSecurityParametersTest(r, params, shared_ptr<VolumePassword>(nullptr),
        -1, shared_ptr<VeraCrypt::KeyfileList>(nullptr),
    shared_ptr<wstring>(nullptr), shared_ptr<Pkcs5Kdf>(nullptr));
}

void AssertEquals(shared_ptr<TestResult> r, size_t expected, size_t actual) {
    if (expected != actual) {
        r->Failed(string("Size differ. Expected") + std::to_string(expected) + ", actual " + std::to_string(actual));
        return;
    }
}

void AssertEquals(shared_ptr<TestResult> r, BufferPtr actual, BufferPtr expected) {
    if (actual.Size() != expected.Size()) {
        r->Failed("Size differ");
        return;
    }
    
    if (!std::equal(actual.Get(), actual.Get()+actual.Size(), expected.Get())) {
        r->Failed("Data differ");
        return;
    }
}

void RevealRedkeyTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating bluekey");
    shared_ptr<Keyfile> kf = CreateBluekey();
    WithBluekey(params, kf);

    r->Phase("revealing redkey");
    shared_ptr<Keyfile> redkeyKf = RevealRedkey(params);

    r->Phase("Reading revealed redkey");
    FilePath redkeyPath = *redkeyKf;
    auto redkey = shared_ptr<File>(new File());
    redkey->Open(redkeyPath, File::FileOpenMode::OpenRead);
    FileStream rkFs(redkey);
    string redkeyData = rkFs.ReadToEnd();
    redkey->Close();

    r->Phase("comparing the data bluekey is based on with revealed keyfile");
    AssertEquals(r, BufferPtr((uint8*)redkeyData.c_str(), redkeyData.size()), *redkeyBuffer);
}

void CreateBluekeyTest(shared_ptr<TestResult> r) {
    // just checks if blue key gets created
    // doesn't check if volume can be mounted, redkey revealed, etc.
    // compares the sized
    shared_ptr<Keyfile> kf = CreateBluekey();
    FilePath bluekeyPath = *kf;
    File bluekey;
    bluekey.Open(bluekeyPath, File::FileOpenMode::OpenRead);
    AssertEquals(r, DEFAULT_REDKEY_DATA_SIZE, bluekey.Length());
}



void CreateVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    CreateVolume(r, params);
}

void MountVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("volume created, mounting");
    EnsureVolumeMounts(r, *params);
}

void DumpVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("volume created, dumping");
    DumpVolume();
}

void MountWithBlueKeyTest(shared_ptr<TestResult> r, VolumeTestParams *params, size_t keyfileSize) {
    r->Phase("creating bluekey");
    EnsureBluekey(params, keyfileSize);

    r->Phase("creating volume");
    CreateVolume(r, params);
    
    // mounting with the same set of parameters
    r->Phase("mounting with the same set of parameters");
    EnsureVolumeMounts(r, *params);


    r->Phase("mounting with redkey");
    shared_ptr<Keyfile> redkey = RevealRedkey(params);

    params->opts->Keyfiles->clear();
    params->opts->Keyfiles->push_back(redkey);
    params->opts->SecurityTokenKeySpec = L""; // do not use security key

    EnsureVolumeMounts(r, *params);
}

void MountWithBlueKeyTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    MountWithBlueKeyTest(r, params, DEFAULT_REDKEY_DATA_SIZE);
}

void CreateVolumeWithBluekeySizeGreaterThanEncryptionKeySizeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    MountWithBlueKeyTest(r, params, DEFAULT_REDKEY_DATA_SIZE + 200);
}


void CreateVolumeWithBluekeySizeLessThanEncryptionKeySizeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    try {
        MountWithBlueKeyTest(r, params, DEFAULT_REDKEY_DATA_SIZE - 92);
        r->Failed("shouldn't use keyfiles less than encryption key size");
    } catch (InsufficientData &e) {
        r->Success();
    }
}

void CreateHiddenVolumeTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    // create outer volume
    r->Phase("creating outer volume");
    auto outerParams = unique_ptr<VolumeTestParams>(new VolumeTestParams());
    *outerParams = *params;

    auto outerCreateOpts = make_shared<VolumeCreationOptions>();
    *outerCreateOpts = *params->createOpts;
    outerParams->createOpts = outerCreateOpts;

    outerCreateOpts->Size = MB(20);
    outerCreateOpts->Type = VolumeType::Enum::Normal;
    outerCreateOpts->Password = GetPassword("outervolumepassword");
    outerParams->opts->Password = outerCreateOpts->Password;
    

    CreateVolume(r, outerParams.get());

    // shared_ptr<VolumeInfo> vi = VeraCrypt::Core->MountVolume(*outerParams->opts);
    // if (!vi) {
    //     r->Failed("couldn't mount created mounted volume to get hidden volume max size");
    // }

    // r->Phase("getting outer volume available space");
    // const DirectoryPath &outerVolumeMountPoint = vi->MountPoint;
    // struct statvfs stat;
    // uint64 outerVolumeAvailableSpace = 0;
    uint64 maxHiddenVolumeSize = outerCreateOpts->Size / 2;
    // if (statvfs(((string)outerVolumeMountPoint).c_str(), &stat) == 0)
    // {
    //     outerVolumeAvailableSpace = (uint64) stat.f_bsize * (uint64) stat.f_bavail;
        
    //     maxHiddenVolumeSize = (4ULL * outerVolumeAvailableSpace) / 5ULL;
    //     uint64 reservedSize = outerCreateOpts->Size / 200;
    //     if (reservedSize > MB(10))
    //         reservedSize = MB(10);
    //     if (maxHiddenVolumeSize < reservedSize)
    //         maxHiddenVolumeSize = 0;
    //     else
    //         maxHiddenVolumeSize -= reservedSize;

    //     maxHiddenVolumeSize -= maxHiddenVolumeSize % outerCreateOpts->SectorSize;

    //     stringstream desc;
    //     desc << "outer volume available space: " << outerVolumeAvailableSpace << ", hidden volume size: " << maxHiddenVolumeSize;
    //     r->Phase(desc.str());
    // }
    // Core->DismountVolume(vi);

    r->Phase("creating hidden volume");
    auto hiddenParams = unique_ptr<VolumeTestParams>(new VolumeTestParams());
    *hiddenParams = *params;

    auto hiddenCreateOpts = make_shared<VolumeCreationOptions>();
    *hiddenCreateOpts = *params->createOpts;
    hiddenParams->createOpts = hiddenCreateOpts;

    hiddenCreateOpts->Size = maxHiddenVolumeSize;
    hiddenCreateOpts->Type = VolumeType::Enum::Hidden;
    hiddenCreateOpts->Password = GetPassword("hiddenvolumepassword");
    hiddenParams->opts->Password = hiddenCreateOpts->Password;
    CreateVolume(r, hiddenParams.get());

    r->Phase("mounting outer volume");
    EnsureVolumeMounts(r, *outerParams);
    
    r->Phase("mounting hidden volume");
    EnsureVolumeMounts(r, *hiddenParams);

    outerParams->opts->Protection = VolumeProtection::HiddenVolumeReadOnly;
    outerParams->opts->ProtectionPassword = hiddenCreateOpts->Password;    
}


void FilesTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("mounting volume");
    auto vi = VeraCrypt::Core->MountVolume(*params->opts);
    auto mp = vi->MountPoint;
    auto volumeSize = vi->Size;

    r->Phase("creating files");
    size_t size = 50;
    size_t step = 50;
    size_t total = 0;
    while (total + size < volumeSize) {
        File f;
        auto filePath = mp.Append(L"test" + std::to_wstring(size) + L".txt");
        f.Open(filePath, File::CreateWrite);
        Buffer buffer(size);
        buffer.Zero();
        f.Write(buffer);
        f.Close();

        total += size;
        step = 2*step;
        size += step;
    }

    r->Phase("dismounting");
    VeraCrypt::Core->DismountVolume(vi);

    r->Phase("mounting back");
    vi = VeraCrypt::Core->MountVolume(*params->opts);
    mp = vi->MountPoint;
    volumeSize = vi->Size;

    r->Phase("checking files");
    size = 50;
    step = 50;
    total = 0;
    while (total + size < volumeSize) {
        File f;
        auto filePath = mp.Append(L"test" + std::to_wstring(size) + L".txt");
        f.Open(filePath, File::OpenRead);
        Buffer buffer(size);
        f.ReadCompleteBuffer(buffer);
        // for (auto i = buffer.Ptr(); i < buffer.Ptr() + buffer.Size(); i++) {
        //     *i = (i - buffer.Ptr()) % 0x100;
        // }
        // f.SeekAt(0);
        // f.Write(buffer);
        f.Close();

        total += size;
        step = 2*step;
        size += step;
    }

    r->Phase("re-creating files");
    size = 50;
    step = 50;
    total = 0;
    while (total + size < volumeSize) {
        File f;
        auto filePath = mp.Append(L"test" + std::to_wstring(size) + L".txt");
        f.Open(filePath, File::CreateReadWrite);
        Buffer buffer(size);
        size_t read = f.Read(buffer);
        for (auto i = buffer.Ptr(); i < buffer.Ptr() + buffer.Size(); i++) {
            *i = (i - buffer.Ptr()) % 0x100;
        }
        f.SeekAt(0);
        f.Write(buffer);
        f.Close();

        total += size;
        step = 2*step;
        size += step;
    }

    VeraCrypt::Core->DismountVolume(vi);
}

void OutOfSpaceTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("mounting volume");
    // EnsureVolumeMounts(r, *params);

    VolumeTestParams p = *params;
    MountOptions opt = *p.opts;
    auto vi = VeraCrypt::Core->MountVolume(opt);
    auto mp = vi->MountPoint;
    auto volumeSize = vi->Size;

    r->Phase("writing oversized file");
    File f;
    auto filePath = mp.Append(L"test.txt");
    f.Open(filePath, File::CreateWrite);
    Buffer buffer(volumeSize);
    try {
        f.Write(buffer);
        f.Close();
        r->Failed("write was successful");
    } catch (...) {
        f.Close();
        VeraCrypt::Core->DismountVolume(vi);
    }

}

void WriteBeyondSpaceTest(shared_ptr<TestResult> r, VolumeTestParams *params) {
    r->Phase("creating volume");
    CreateVolume(r, params);

    r->Phase("mounting volume");
    VolumeTestParams p = *params;
    MountOptions opt = *p.opts;
    auto vi = VeraCrypt::Core->MountVolume(opt);
    auto mp = vi->MountPoint;
    auto volumeSize = vi->Size;


    auto smallFileSize = KB(100);
    auto largeFileSize = volumeSize - smallFileSize;

    r->Phase("writing large file");
    File f;
    auto filePath = mp.Append(L"test-large.txt");
    f.Open(filePath, File::CreateWrite);
    Buffer buffer(largeFileSize);
    buffer.Zero();
    f.Write(buffer);
    f.Close();


    r->Phase("writing small file by byte");
    filePath = mp.Append(L"test-small.txt");
    f.Open(filePath, File::CreateWrite);
    Buffer smallBuff(1);
    
    for (size_t i = 0; i < smallFileSize; i++) {
        *smallBuff.Ptr() = (i % 0x100);
        try {
            f.Write(smallBuff);
        } catch (...) {
            f.Close();
            VeraCrypt::Core->DismountVolume(vi);
            return;
        }
    }
    f.Close();
    r->Failed("write was successful");
}


vector<VolumeTestParams> GenerateCombinations() {
    auto EAs = VeraCrypt::EncryptionAlgorithm::GetAvailableAlgorithms();
    auto hashAlgos = VeraCrypt::Hash::GetAvailableAlgorithms();


    vector<VolumeTestParams> res;

    for (auto ea : EAs) {
        for (auto ha : hashAlgos) {
                ea->GetName();
                ha->GetName();
                shared_ptr<Pkcs5Kdf> kdf = Pkcs5Kdf::GetAlgorithm (*ha);
                
                wstringstream wname;
                wname << ea->GetName() << "_" << ha->GetName() << "_" << kdf->GetName();
                
                string name = StringConverter::ToSingle(wname.str());
                auto createOpts = GetCreateOpts(name);
                auto mountOpts = GetOptions(name);
                createOpts->EA = ea;
                createOpts->VolumeHeaderKdf = kdf;

                mountOpts->Kdf = kdf;

                res.push_back(VolumeTestParams{name, mountOpts, createOpts});
            }
        }
    return res;
}


int main() {
    SetUp();
    VeraCrypt::Testing t;

    
    
    // t.AddTest(WithDefaultParams("create volume with bluekey, size > encryption size", &CreateVolumeWithBluekeySizeGreaterThanEncryptionKeySizeTest));
    // t.AddTest(WithDefaultParams("create volume with bluekey, size < encryption size", &CreateVolumeWithBluekeySizeLessThanEncryptionKeySizeTest));
    // t.AddTest(WithDefaultParams("files test", &FilesTest));
    // t.AddTest(WithDefaultParams("create hidden volume", &CreateHiddenVolumeTest));
    // for (auto p : GenerateCombinations()) {
    //     t.AddTest(WithParams(p.caseName, MountVolumeTest, p.createOpts, p.opts));
    // }
    // t.Main();
    // TearDown();
    // return 0;

    /*
     * Test not related to the volume
     */    
    t.AddTest("create blue key", &CreateBluekeyTest);
    t.AddTest(WithDefaultParams("reveal redkey", &RevealRedkeyTest));

    /*
     * Test related to volume creation/mounting/changing
     */
    t.AddTest(WithDefaultParams("create volume", &CreateVolumeTest));
    t.AddTest(WithDefaultParams("create hidden volume", &CreateHiddenVolumeTest));
    t.AddTest(WithDefaultParams("create volume with bluekey", &MountWithBlueKeyTest));
    t.AddTest(WithDefaultParams("create volume with bluekey, size > encryption size", &CreateVolumeWithBluekeySizeGreaterThanEncryptionKeySizeTest));
    t.AddTest(WithDefaultParams("create volume with bluekey, size < encryption size", &CreateVolumeWithBluekeySizeLessThanEncryptionKeySizeTest));
    t.AddTest(WithDefaultParams("change password", &ChangePasswordTest));
    t.AddTest(WithDefaultParams("add keyfile to the volume", &AddKeyfileToVolumeTest));
    t.AddTest(WithDefaultParams("add bluekey to existing volume", &AddBluekeyToVolumeTest)); 
    t.AddTest(WithDefaultParams("remove blue key from existing volume", &RemoveBluekeyFromVolumeTest));
    t.AddTest(WithDefaultParams("use bluekey as redkey", &UseBluekeyAsRedkeyTest));
    t.AddTest(WithDefaultParams("use token key without keyfiles", &UseTokenKeyWithoutKeyfilesTest));
        
    t.AddTest(WithDefaultParams("test creating files of differing sizes", &FilesTest));
    t.AddTest(WithDefaultParams("out of space test", &OutOfSpaceTest));
    t.AddTest(WithDefaultParams("test writing beyond available space", &WriteBeyondSpaceTest));
    

    /*
    *  Parameterized tests
    *    The combination of parameters covers all possible security options (keyfiles, passwords, pim, truecrypt, algos)
    *    and filesystems
    */

   TestSuite *algosSuite = new TestSuite();
   algosSuite->StopOnFirstFailure();
   for (auto p : GenerateCombinations()) {
        algosSuite->AddTest(WithParams(p.caseName, MountVolumeTest, p.createOpts, p.opts));
   }

   t.AddTest(algosSuite);

    t.Main();
    TearDown();
}
