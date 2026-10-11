# Dormant path observer product profile candidate v6

Measured from the seven REFROZEN_3 Hermes CMake images on 2026-10-11. The previous v5 source-only profile was independently approved for the earlier test bytes and is preserved in reprofile evidence. This v6 candidate binds the updated injected test, test adapter, archive and all measured build inputs: compiler depfiles, workspace and external headers, CMake inputs, actual link-map SDK `.tbd` rows, SDK/toolchain bytes, raw Mach-O profiles and qualified nm/otool closure. Its JSON SHA is pinned in the gate. This candidate has no execution authority until independent CODE and NATIVE review and coordinator approval. Installed authority and readiness remain false. A changed pinned input requires another reviewed profile.

```json
{
  "archive_members": [
    "path_observer_os_darwin_v1.c.o",
    "path_observer_core_v1.c.o"
  ],
  "archive_sha256": "a28bea42a9d24d1f5aa8e8a1f17eae80bf3fb51d2a39a47e8292674b4e2cd2d5",
  "cache": {
    "arch": "arm64",
    "compiler": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
    "deployment": "27.0",
    "sdk": "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
  },
  "cmake_sources": {
    "dependencies_sha256": "95bc287cf5aa23905edfae7ceb7961db63d6c61b6c78e6facdf2d7443bf61a02",
    "external_sha256": {
      "/opt/homebrew/share/cmake/Modules/CMakeCCompiler.cmake.in": "0cd5ed7679dad2d31d394a0208d5ee4a46c80461d311259a6f3aaae8d91d3c03",
      "/opt/homebrew/share/cmake/Modules/CMakeCCompilerABI.c": "ec2b667c9497aa6199b87cc9f7800027f7c06a59cf5f92a3ab455bb7e108862e",
      "/opt/homebrew/share/cmake/Modules/CMakeCInformation.cmake": "ce7d0799f61032c5caec45d26c1d7afe7f59ff9377e87f176aa1649caa1bf979",
      "/opt/homebrew/share/cmake/Modules/CMakeCommonLanguageInclude.cmake": "63e32c7d86299cdb1d804e2695ddc5e6f2553f5d016ca259290dc7e98a679f89",
      "/opt/homebrew/share/cmake/Modules/CMakeCompilerIdDetection.cmake": "05200b2727d7d0e4d0794e3316977bb4ce2aac4f60b0f3d0c13dc32248b3e4cc",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineCCompiler.cmake": "d48321151f3dbcd2e19eb1ee2da33a8c1c353778a135d040530b5468be0d620b",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineCompiler.cmake": "21f324bbfd6c6c8aff0b656d152ca320f2d9f65475dd083ce811e44eed0c3781",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineCompilerABI.cmake": "4d3fbcc46648144d52247304ec75f43833ecd24c015a5cbd192ac5d42d2ce75a",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineCompilerId.cmake": "2d4a1b5c471884cbd2555eef4c503a61471be73dceef22bca8823a7580f029b2",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineCompilerSupport.cmake": "3347293d9632813ace1db80d624166845bfcb5d4f1a7327f26e99b913899eaa9",
      "/opt/homebrew/share/cmake/Modules/CMakeDetermineSystem.cmake": "c9a0e1cd987f813b8138039b12f5cdee70f3c7db1534c9853f3ab1c083d2276d",
      "/opt/homebrew/share/cmake/Modules/CMakeFindBinUtils.cmake": "e54830c57817415d8bdd1db1f43b1f60a8bcbb8eb1d9f8dd25f5af7432db758a",
      "/opt/homebrew/share/cmake/Modules/CMakeGenericSystem.cmake": "51d5fba7b8e3492a6246ba29d192f8bb66888541ef987d1e41dff37213c2d2e9",
      "/opt/homebrew/share/cmake/Modules/CMakeInitializeConfigs.cmake": "1301ec4871a37c30a333a76084d33a4af82a5b6daaa2d6afbb7a7369b00097e5",
      "/opt/homebrew/share/cmake/Modules/CMakeLanguageInformation.cmake": "4bfe748efa0ce01561bc59d862cc8bed6dfeef88fcdb8d2cf679d40e7f1b6273",
      "/opt/homebrew/share/cmake/Modules/CMakeParseImplicitIncludeInfo.cmake": "f35c26ecfc38d2a37e379d78a8f702eceba558a8c3cf7f1c20783d32caa8606d",
      "/opt/homebrew/share/cmake/Modules/CMakeParseImplicitLinkInfo.cmake": "7604454b30adf8f5543e6b99db80b348d11ec0660c51737058f8f0b60098696a",
      "/opt/homebrew/share/cmake/Modules/CMakeParseLibraryArchitecture.cmake": "05ce000d8f6689b1e9fff7be6b7aff82f72eabc65684d025f41916c43f6db8fe",
      "/opt/homebrew/share/cmake/Modules/CMakeSystem.cmake.in": "60b5167875d6a01de4fb96c784a4e01d56f365f096fa9a257c6b6b6d9669e49a",
      "/opt/homebrew/share/cmake/Modules/CMakeSystemSpecificInformation.cmake": "664346220947100185616597c9d2f9194019cfa5a3fd92df53bed88536ec4426",
      "/opt/homebrew/share/cmake/Modules/CMakeSystemSpecificInitialize.cmake": "4d77e453de4f917e4a91a84699b8e14c71fea1f269fe5460ebe773111cf9c566",
      "/opt/homebrew/share/cmake/Modules/CMakeTestCCompiler.cmake": "ea4efaac2bebfb2cdd36c09bb4c972b7c92c3d0004194c6bc1ca417e605b2349",
      "/opt/homebrew/share/cmake/Modules/CMakeTestCompilerCommon.cmake": "c5acc2709a55ac3859bb8af5bd84e6ed87ee8e2edf885352b5d709851275e488",
      "/opt/homebrew/share/cmake/Modules/CMakeUnixFindMake.cmake": "6b94a7963399c955caaae4d42296b8a98dab7fac811e11ca10000d8079362649",
      "/opt/homebrew/share/cmake/Modules/Compiler/ADSP-DetermineCompiler.cmake": "3a83e2929cd66ec80b57e5af63701caf268bc72e9bd6fb1d5e27993ab7abf8f1",
      "/opt/homebrew/share/cmake/Modules/Compiler/ARMCC-DetermineCompiler.cmake": "170e68c9d6932c7287c27e7fbf77e4b7219f6b8c395b2f0b1223b672c5b2c568",
      "/opt/homebrew/share/cmake/Modules/Compiler/ARMClang-DetermineCompiler.cmake": "6d0786b255446546870e4aab0ffba84796b506e50c201df0621d943ceb1f8aab",
      "/opt/homebrew/share/cmake/Modules/Compiler/AppleClang-C.cmake": "9729eda3548e811025a03a59543454f0a91d22eef242fa4a3e0de57d2ab08e4b",
      "/opt/homebrew/share/cmake/Modules/Compiler/AppleClang-DetermineCompiler.cmake": "12c2f516b23659ab0d8e6624f5e64e5995f57116137b18fea2d82d41b762c6b8",
      "/opt/homebrew/share/cmake/Modules/Compiler/Borland-DetermineCompiler.cmake": "3549196d22c963f160b076f8079d484fb51f1a3db53095f62f63de3391d48b6e",
      "/opt/homebrew/share/cmake/Modules/Compiler/Bruce-C-DetermineCompiler.cmake": "2574246c53e79f71d7582e9ff79e2dbe7ec3f8bceb61acbdccd366ada6618887",
      "/opt/homebrew/share/cmake/Modules/Compiler/CMakeCommonCompilerMacros.cmake": "4b10a42437e47e3783c7037d1467bd22990673478449015e7423162a5f015ef7",
      "/opt/homebrew/share/cmake/Modules/Compiler/Clang-DetermineCompiler.cmake": "9c246617fb086c4ede131ccf4aec2c029683f2d3ff1c5c32ff045b6f409d1cd6",
      "/opt/homebrew/share/cmake/Modules/Compiler/Clang-DetermineCompilerInternal.cmake": "b56db5d774d273d696df8302ce3cd3421047190188de796faa3ba7bb24f31af9",
      "/opt/homebrew/share/cmake/Modules/Compiler/Clang.cmake": "84025c6ea7edb05ccf45793f96e5a9d89bc64f061f89a3bd1e24ba0c4b75af51",
      "/opt/homebrew/share/cmake/Modules/Compiler/Compaq-C-DetermineCompiler.cmake": "863ac7e7253606ebca32f45b5f87347be660b2ad303fb241c462b3a0494a051f",
      "/opt/homebrew/share/cmake/Modules/Compiler/Cray-DetermineCompiler.cmake": "4f5900fb5ab3d540b1353ac5ead8aabb9eef8a02eafeb728e41983c78bd42553",
      "/opt/homebrew/share/cmake/Modules/Compiler/CrayClang-DetermineCompiler.cmake": "0ad9278048546643a9733363104f262eb3c5c78d579e2cff13b5661abf7573e0",
      "/opt/homebrew/share/cmake/Modules/Compiler/Diab-DetermineCompiler.cmake": "b073646a0ecca179fc7506d67469b5d8caef0d3dab9ae24af542d1bf1b9ece80",
      "/opt/homebrew/share/cmake/Modules/Compiler/Embarcadero-DetermineCompiler.cmake": "95dba41c6d8ad9b23ca5b0e82e40c18c4585e3c6ce4aac89f527b6f91f934610",
      "/opt/homebrew/share/cmake/Modules/Compiler/Fujitsu-DetermineCompiler.cmake": "3f126cceb88ba33522b35ad421bb3db9f318f17fa1ca33f8446f4b4f38435cab",
      "/opt/homebrew/share/cmake/Modules/Compiler/FujitsuClang-DetermineCompiler.cmake": "d277a602aa98283fcd587ac0d57d1fcb78ca2d0c7a0178940c7833b758687135",
      "/opt/homebrew/share/cmake/Modules/Compiler/GHS-DetermineCompiler.cmake": "18f8b5082121fc69005ea2f324111faa6bbe7625a432969fb77c90643f067045",
      "/opt/homebrew/share/cmake/Modules/Compiler/GNU-C-DetermineCompiler.cmake": "b0103d56bd2ab3ae3fa34059d50dc3f74d639d6e894fc359f2c52a04ba7617ca",
      "/opt/homebrew/share/cmake/Modules/Compiler/GNU.cmake": "6258098e0b8597ec293acca87c5f3cb84d19caa69d0a8fd5f8216d319f6b278d",
      "/opt/homebrew/share/cmake/Modules/Compiler/HP-C-DetermineCompiler.cmake": "926b28ec5b4ed6c2cc460880512fa3c637c184a843beb72134270acd5089604f",
      "/opt/homebrew/share/cmake/Modules/Compiler/IAR-DetermineCompiler.cmake": "55bbea1fffa2cf38bfc194adc6ed6f988709cfd481156d799194bc34bc729d66",
      "/opt/homebrew/share/cmake/Modules/Compiler/IBMCPP-C-DetermineVersionInternal.cmake": "61b7e77a33221dc1a96e38e78d94d1e721e596a6ea4562e5f73bf5488a55be3e",
      "/opt/homebrew/share/cmake/Modules/Compiler/IBMClang-C-DetermineCompiler.cmake": "6dc6dfaff58e0a98ab638bf95202a68980326794ce5e8638d2a03c905cd2afa9",
      "/opt/homebrew/share/cmake/Modules/Compiler/Intel-DetermineCompiler.cmake": "ce575bb9d12659038600410754c8429a0296d832d788e0d19fb8843fc83b8217",
      "/opt/homebrew/share/cmake/Modules/Compiler/IntelLLVM-DetermineCompiler.cmake": "6fee15705bf16dc7f57b806d9e763033d5b4d249ae37e4b926e4591eb04988fb",
      "/opt/homebrew/share/cmake/Modules/Compiler/LCC-C-DetermineCompiler.cmake": "afca3caa45fdc1947f26bc181c3e28e083f0bd46a8a9c88e66c5f35f6d3f0bda",
      "/opt/homebrew/share/cmake/Modules/Compiler/MSVC-DetermineCompiler.cmake": "b272204b9d05e848bf5c023d805281ae8edba81b3f5e0345f180133c5a2b18f6",
      "/opt/homebrew/share/cmake/Modules/Compiler/NVHPC-DetermineCompiler.cmake": "60caf9dc1f1c1d3d74b40a68a543b5ba8641ad46f1f147236147e731d8459afe",
      "/opt/homebrew/share/cmake/Modules/Compiler/NVIDIA-DetermineCompiler.cmake": "08788973c752e4f8ddda31c63dbd38383fefd4eb1d1cc142118622406954405c",
      "/opt/homebrew/share/cmake/Modules/Compiler/OpenWatcom-DetermineCompiler.cmake": "0afef594e2059e454b38969469116e41f61b474c3a372391cb9cd65fc0f2ef36",
      "/opt/homebrew/share/cmake/Modules/Compiler/OrangeC-DetermineCompiler.cmake": "57752dfe4fec6efd9274f90884f2da25248149d2d0fcf73ead519c98370eeb99",
      "/opt/homebrew/share/cmake/Modules/Compiler/PGI-DetermineCompiler.cmake": "4d77f5a358f48f1c5d14750723b35dc4f4635d9dffe9aeaaba164841a6e475af",
      "/opt/homebrew/share/cmake/Modules/Compiler/PathScale-DetermineCompiler.cmake": "c0b5eda8f936c17ccc11dbf39b3e5958ac1d8ddb4d455a2ad47d89478dda7637",
      "/opt/homebrew/share/cmake/Modules/Compiler/PellesC-DetermineCompiler.cmake": "5659cc8063c8551b38ada9685ea03ccd719c32e4c0aa98baf55910f750ee6ff6",
      "/opt/homebrew/share/cmake/Modules/Compiler/Renesas-DetermineCompiler.cmake": "23a9e717504eda82a3f40bb8bc0db5dfd8d22b742a4a40bfefb0aa1326c4b870",
      "/opt/homebrew/share/cmake/Modules/Compiler/SCO-DetermineCompiler.cmake": "b3ca14336760eee849c325f5466edc15555d0883b0d58c2a3d107fcbce623e89",
      "/opt/homebrew/share/cmake/Modules/Compiler/SDCC-C-DetermineCompiler.cmake": "09c9b87a63f0f6495b06412a0b9ece0b5689abe9c24c03efb966475058e23a78",
      "/opt/homebrew/share/cmake/Modules/Compiler/SunPro-C-DetermineCompiler.cmake": "53dfb09317ad18380d167259bb0f64fca5b00894f83c5ce016befeb55018adfb",
      "/opt/homebrew/share/cmake/Modules/Compiler/TI-DetermineCompiler.cmake": "a5d3b4771421f42854e7bcfbfcdde26cdbb01d9fd85f0c3f79f17e75b0680fb5",
      "/opt/homebrew/share/cmake/Modules/Compiler/TIClang-DetermineCompiler.cmake": "b1a0120c8035d4439d1d4a36c6a131ccc17916042686afb289929c2a40fefcd5",
      "/opt/homebrew/share/cmake/Modules/Compiler/Tasking-DetermineCompiler.cmake": "4891c24b0e2bdf2142fa525e8b576e64f441a4e2899c497d397f1e058d506297",
      "/opt/homebrew/share/cmake/Modules/Compiler/TinyCC-C-DetermineCompiler.cmake": "1d2c00ccdb5ab5a0674fc1a79520e06484750fd9050a805056fef69b49aec847",
      "/opt/homebrew/share/cmake/Modules/Compiler/VisualAge-C-DetermineCompiler.cmake": "76cf7fef13b57d994d5c8109bb2d822dd363d4859e1d16ff2957bb13e394e764",
      "/opt/homebrew/share/cmake/Modules/Compiler/Watcom-DetermineCompiler.cmake": "a6a6951831b5973393a6a318b3527d3d68330f02b434f8b5d3100e9dfe2b758c",
      "/opt/homebrew/share/cmake/Modules/Compiler/XL-C-DetermineCompiler.cmake": "b117154cfa3c0b93ebce821f027e93af36f7c53c9fdd95f13cdafa72683c861a",
      "/opt/homebrew/share/cmake/Modules/Compiler/XLClang-C-DetermineCompiler.cmake": "e0072f3e3c62f3bff0aebe08db2989cd5704ead33db279c90bccbb9426af1405",
      "/opt/homebrew/share/cmake/Modules/Compiler/zOS-C-DetermineCompiler.cmake": "2184c15616ba508c5345214d94064bad89bffc02e18fab5ad70f7c4ebf0a796f",
      "/opt/homebrew/share/cmake/Modules/Internal/CMakeCLinkerInformation.cmake": "f697f7f5d0337e0918a0a425f6d9d5cf6b4d35a3944129902b43ca3bcb67802f",
      "/opt/homebrew/share/cmake/Modules/Internal/CMakeCommonLinkerInformation.cmake": "d1f25fc58b1c659e22a817dc41e15746e153bfa398af7edaf592dc0f721dd926",
      "/opt/homebrew/share/cmake/Modules/Internal/CMakeDetermineLinkerId.cmake": "7b0c6ac35cc8e7e7c33cd9b9df93fbe11eec054f956ef22df920363c27c105d6",
      "/opt/homebrew/share/cmake/Modules/Internal/CMakeInspectCLinker.cmake": "5006650dbc3edb6254f8b7effae5cd0ed22c881134cbb00a8f3d97388be90383",
      "/opt/homebrew/share/cmake/Modules/Internal/FeatureTesting.cmake": "719d01966a85ad67c8195015e0b648e7e73e4a09f326107ed9185a5d18a9b1f1",
      "/opt/homebrew/share/cmake/Modules/Linker/AppleClang-C.cmake": "050ab4315e64b068710b1d0be184c281532df4bb6c5d24b91e42a1c7c970b8a6",
      "/opt/homebrew/share/cmake/Modules/Linker/AppleClang.cmake": "4a18eebfdd8c7aa800fceadc8e9ef242bf7b4f57fb5a54d3dcac7e5277614dbb",
      "/opt/homebrew/share/cmake/Modules/Platform/Apple-AppleClang-C.cmake": "92f633830d414f52fcd1e2ed9a615e5a6c70283e3b06b6ba3ce9812c5b3bc5c2",
      "/opt/homebrew/share/cmake/Modules/Platform/Apple-Clang-C.cmake": "c65a51c8afcb89dc4757ea1e1b07e97d466ce3cdc8563c3c8c2719fadc9ddd09",
      "/opt/homebrew/share/cmake/Modules/Platform/Apple-Clang.cmake": "64ec25e27b86045ca1120bb402b09c2707537bad0657e4c29bd544297141048a",
      "/opt/homebrew/share/cmake/Modules/Platform/Darwin-Initialize.cmake": "179623773d33a1a082f15413c41776a21e4f3a7cad0e09eb953584475c719255",
      "/opt/homebrew/share/cmake/Modules/Platform/Darwin.cmake": "8e19ed912c8620791f4dbac14d162cd58569aab9f7499c539434b8f0619e6613",
      "/opt/homebrew/share/cmake/Modules/Platform/Linker/Apple-AppleClang-C.cmake": "9ef6de56d7b4a3950412266c8bf4fe41a45f534dc86e241634d50d46bc29e6a7",
      "/opt/homebrew/share/cmake/Modules/Platform/Linker/Apple-AppleClang.cmake": "dbffb6415ac9984cdd905fac4578066ed1031c941ef252e68a669a71200a221c",
      "/opt/homebrew/share/cmake/Modules/Platform/UnixPaths.cmake": "1039256a0e78c6fe1c31234feef17a54e2dda460a3bc2949984f3f8c6df900f5"
    },
    "generated_sha256": {
      "${BUILD}/CMakeCache.txt": "5ce3229c34f133d8de3d0142f6b129c106ced750003a2f3053b8aa1d0f9036e7",
      "${BUILD}/CMakeFiles/4.4.4/CMakeCCompiler.cmake": "2e8c5e63df83e7886f9a5dbaca99283929ed4902b158befdb9a4bb17255a0288",
      "${BUILD}/CMakeFiles/4.4.4/CMakeSystem.cmake": "0a827d18a29e4cb19953a47f56571b676c06dc1ca6c0fcce36bec424920fbb81"
    },
    "generator_sha256": "819650a48bdf2138f7e071d90b4267adc6995cb90ad45d152ab1d5d4d4527f1e",
    "workspace_paths": [
      "native/darwin_bootstrap/CMakeLists.txt"
    ]
  },
  "core_object_sha256": "f9969f793544be8f3a2d6f08c45b5df6ec3f70499168a324705ddd4674a2bc2d",
  "default_graph": [
    "bee_hermes_a2a",
    "bee_hermes_a2b_fd7",
    "bee_hermes_a2c_phase1",
    "bee_hermes_a2c_attempt",
    "bee_hermes_a2c_final",
    "bee_hermes_a2c_stage0",
    "bee_hermes_a2c_phase2_attempt",
    "bee_hermes_a2c_phase3_final",
    "bee_hermes_a2c_phase3_stage0",
    "bee_hermes_a2c_phase3_attempt",
    "hermes_bee_install_preflight",
    "bee_hermes_install_preflight_test"
  ],
  "depfiles": {
    "external_sha256": {
      "${SDK}/SDKSettings.json": "7b93ad7e534cc4b31c6a4e39d19b5e0288acf2168c2649479a796d1cb51939fb",
      "${SDK}/usr/include/Availability.h": "d39d74d343b5f3dc147525c5f4ba99c1ae9133bccc57eb6205a74d0ba99d92cb",
      "${SDK}/usr/include/AvailabilityInternal.h": "4b7f7e27b33d7ccdcc21654b0016eaa4187ce63387eb135babf269cddedcb9b0",
      "${SDK}/usr/include/AvailabilityInternalLegacy.h": "4c15ffce0467946a20beaa2eb25eba2cbe1788c620aaeb2516c39436a88fe276",
      "${SDK}/usr/include/AvailabilityVersions.h": "e9f8f7e0eb62c904cf7dca1fd6ba2fe28ba7a382cd9b5339fd03f6de13e66d02",
      "${SDK}/usr/include/CommonCrypto/CommonDigest.h": "83a9705bbc8d44f27ee61801064ee99288496a038d623f152aa30db6819e9ca6",
      "${SDK}/usr/include/CommonCrypto/CommonHMAC.h": "52384fdb358ceb01a224f4961dfb1330a146168e4b385b78f0ade884a9e33f7e",
      "${SDK}/usr/include/_abort.h": "ad37627745fd324a640fa93c5f9909250c036d577457090a1e72ee939cd7fc7b",
      "${SDK}/usr/include/_bounds.h": "3d9f049f5fac54421170fa34a845b244dce7b83a3c68ddd589909df759854700",
      "${SDK}/usr/include/_ctermid.h": "73ac20b763ff6e1c328563bbd125e3eaa78a367eb92c867626a047ae4ab391b3",
      "${SDK}/usr/include/_printf.h": "d90a7023063c22dfb77d3034163d2c35908f3103b458a83659b7f7b38d2d0cb2",
      "${SDK}/usr/include/_stdio.h": "8417242466f6df6890587974393e97bb0aeac8caeb80cdf82a4e03a97e6d4660",
      "${SDK}/usr/include/_stdlib.h": "19041cffa8a37743cc48561f75eccd96917125a7dc4d785a78049972ab1a911c",
      "${SDK}/usr/include/_string.h": "18ce21b76c6876087aae9053dcdb81182adbdb0405afc82f36d8edc000c06b3a",
      "${SDK}/usr/include/_strings.h": "76b984c39538b145bcb8a930538e07ce446e9d4ace00916d6110c775151d800e",
      "${SDK}/usr/include/_time.h": "a3dceadf2c95133018af363187829ca072d85a93d69f9682a2e4fb993902f28d",
      "${SDK}/usr/include/_types.h": "532c4b0f11274f6b10875db65e154e6cedaa20fdd189f5f40a8780c9a4c39449",
      "${SDK}/usr/include/_types/_intmax_t.h": "215f90a4efdca4991735be55a1ff701964dde07d8b4a8382ec8ed41ecbf5f115",
      "${SDK}/usr/include/_types/_uint16_t.h": "adf29323b0ecb87cbc43ac3ff25c096de7a214ceb90007c2828616151c66ad37",
      "${SDK}/usr/include/_types/_uint32_t.h": "951131475ec815813c8ff40d5e875029cd968334fd3a42d5a65fbe7851d1718c",
      "${SDK}/usr/include/_types/_uint64_t.h": "a5692cddb9c42d1b55ebcd6fa445b212c4b0c46db4583aaf3293ed6386d3d0d6",
      "${SDK}/usr/include/_types/_uint8_t.h": "0a5c0353c8410f5e502db7971d987ac83a9ec3148905f10984c78152f541de68",
      "${SDK}/usr/include/_types/_uintmax_t.h": "0b154b16a3945edff78f00321d90a662d522e197c08e7de3b68f0ea44ae0d042",
      "${SDK}/usr/include/alloca.h": "5e956d0cffbf6d069d2cc9cee52686e1e7b73e3e2939cfb3fd3a7ca096bd8980",
      "${SDK}/usr/include/arm/_endian.h": "488530aceccfa1f364f2850a5f2956e22436db8b12b33d2a41567c4ac9d60788",
      "${SDK}/usr/include/arm/_limits.h": "b64325f6b5aba08a361b7b8e537df3d8d193538c1d6329a4c4a7e72f5aa63478",
      "${SDK}/usr/include/arm/_mcontext.h": "6af56aec1a82613dbd54b09d95eaf96fa7b9443a4cf4c7e9ba689f6de6047186",
      "${SDK}/usr/include/arm/_param.h": "7df463cd4e47b0bcef897e82b90a5e108715b420f109568864ac720973b85397",
      "${SDK}/usr/include/arm/_types.h": "4f0bde85f9a41cc7d30fff22ebd7e8f4eb206a55a926eda012a2e7481e3524fa",
      "${SDK}/usr/include/arm/endian.h": "60bd5d1363d89d52e5cfc95b83a35d392a8315835f9d60089d4e05b8f4d1cc68",
      "${SDK}/usr/include/arm/limits.h": "dcfa3b29f6a6c6fda1ce6f362a6eb2b27cc756ef5051c3a48641365660265139",
      "${SDK}/usr/include/arm/param.h": "1aef582d154132ed20b12550abd7bf8893e67ea1e91c3db49fd52872e4ad4ea5",
      "${SDK}/usr/include/arm/signal.h": "de0bc923b92bd88f3bd8bcd38b20f8123277732d7d3309cb2a5bdc60bb4dd8c6",
      "${SDK}/usr/include/arm/types.h": "b9eccd5a3feb3a62e22e42936656c8822e7e3e8708d759b1512deee05f682f0d",
      "${SDK}/usr/include/bsm/audit.h": "3bac25ab2d4dd6a440517b737f262cbfb6382049d618f01ad3856c23233adf04",
      "${SDK}/usr/include/errno.h": "ff95a158e0799dcf0622e83882e64d88f1783b98a91d9b206bcba2a12f8425e6",
      "${SDK}/usr/include/fcntl.h": "289f3be20c07d8eae5589f43994cfdb5fb33b3b099a6aee67f63e00d90039a8f",
      "${SDK}/usr/include/gethostuuid.h": "0a4f4be11c5503f991d5e44f38ee8d50d8b5d4dbfaa5d0da361027968ea4d2c8",
      "${SDK}/usr/include/grp.h": "0f372957378505d685eab6b328686ee09d1b8614f5ebed5a1a6d1eb643aa868e",
      "${SDK}/usr/include/libkern/_OSByteOrder.h": "f0febaef6f9ec75339ebdd896dab2a6d1a1934628d76098f165f1db1b4b74c14",
      "${SDK}/usr/include/libkern/arm/_OSByteOrder.h": "7c686aa04afa38a20a0163eccca9941aeb8328779884c2603d8a9a773896a677",
      "${SDK}/usr/include/libproc.h": "246d87709fc6b9157ce5cf3c475656ac48e0e1ae8bbdc46cf45acd34294448cd",
      "${SDK}/usr/include/limits.h": "4e09d7a2307887fe787c65e31d63747720c4d462b7ba3bf8f45e401d74f0b246",
      "${SDK}/usr/include/mach/arm/_structs.h": "30e201a2bf77b2b09163250db64760f303903590904a3daabd9b96cbcba19b7e",
      "${SDK}/usr/include/mach/arm/boolean.h": "03ceda8c88250b93a3bebca92e03dd558e13fe68e83eff6bba5db32f95b48b6d",
      "${SDK}/usr/include/mach/arm/exception.h": "68feaf7014b68e900785d399ea23188ad36dff252010def17613208b584aa03e",
      "${SDK}/usr/include/mach/arm/kern_return.h": "c06cb329babef0663cd8c86b5e5f545fafc8d8659bb83cef75506281187ef9f1",
      "${SDK}/usr/include/mach/arm/thread_state.h": "ab91af1d14bd3ff1e028709e7d4db215eac0df620ff81ad3aa38ae295a50aed0",
      "${SDK}/usr/include/mach/arm/thread_status.h": "652760f46ee3b456efdcfcc5b5710a0bbc3aa30e0a1495f45ebdd038b323a693",
      "${SDK}/usr/include/mach/arm/vm_types.h": "4256065e3413a8a506492ff4e4c46596076a56e44db7c850efbc832c8b12fbb1",
      "${SDK}/usr/include/mach/boolean.h": "c050da6ed29d186ac403c0ba187031aca3ac32da2b4e618e0d0c8ba1b7665523",
      "${SDK}/usr/include/mach/error.h": "bd288ca8dab37bee91ab75cb3ed6238be9bbffae3c687f4cb54057bba6467d8d",
      "${SDK}/usr/include/mach/exception_types.h": "8b7c3999787e8017b1127faac0e7d6885524a6b7ca05fb88a705773e0dd1e64a",
      "${SDK}/usr/include/mach/kern_return.h": "2d4b89f7cf91cf7bffafe457cdba8884c3f2e5596a9ef7d5e4a9ea4b239558d8",
      "${SDK}/usr/include/mach/machine.h": "00d57dcf5a8332ba5a759b447f8305b3ef8bf15a9025c142af04e13c2a5b14f5",
      "${SDK}/usr/include/mach/machine/_structs.h": "410350f04225bf139bd89f1a99418a55734e4ab2101bb93dc301f790a130f59c",
      "${SDK}/usr/include/mach/machine/boolean.h": "a22e0c8c541b9117a86d85ab4a977eda49917a9867b24576f5972b6fa6554f23",
      "${SDK}/usr/include/mach/machine/exception.h": "50a572de0f7b9ddd7925debb3de372a1535baa0a6955c53e5709cbbf3947be94",
      "${SDK}/usr/include/mach/machine/kern_return.h": "160d3b4460244b7f469a34f3030071bd717d2918cb748527c1207ca78310d51d",
      "${SDK}/usr/include/mach/machine/thread_state.h": "c8b6a465623bee017fbaecb5fffbe86d96b34bc657f026950389e0f760ad02f3",
      "${SDK}/usr/include/mach/machine/thread_status.h": "756a3db7289b7cea839f9bd9e9556427ab3c9effa77e552bdc9b2e6e096d2f7c",
      "${SDK}/usr/include/mach/machine/vm_types.h": "1c2a4ff4b5843ded602775a447494f353a295015ca8d913a0a13439f4ee28654",
      "${SDK}/usr/include/mach/message.h": "86e9e87ba2a736236613f2c0a8563dbacaeec1a761654b12812eaf8599b55e67",
      "${SDK}/usr/include/mach/port.h": "959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185",
      "${SDK}/usr/include/mach/thread_status.h": "ebffe87f2b535072fb6d6da945fbcdd6da7e6eab26bcb5383807d34e0299162b",
      "${SDK}/usr/include/mach/vm_types.h": "c6d1d28e8a69a0e645002e24c051aae10738fd3cbb73a0dbabecc559aefc871a",
      "${SDK}/usr/include/mach_debug/ipc_info.h": "99cc388f6be292feea3ecf344dacb5d0e43f9eae10eb7e3957dee679fc929828",
      "${SDK}/usr/include/machine/_endian.h": "17eb7d38845502ce04aac3ab709dffeb4ec253781051b5d7894703e9786730de",
      "${SDK}/usr/include/machine/_mcontext.h": "9d3425653d2a1623d785dee4601c3c00e05f4797d7e840b00f17d529f8c6c51e",
      "${SDK}/usr/include/machine/_param.h": "a439dd9d92d11570d734c87c634f32f85dc8f98624c72acc70e2f0bfbcd73e1a",
      "${SDK}/usr/include/machine/_types.h": "f27264f8fdec9f164b4fc2b556f666ed7c5c0e5b88fd9f23db0b731ffa6cf864",
      "${SDK}/usr/include/machine/endian.h": "37f9e1c8599a729e605477a5b6a77cea727fa66816e4585d0dd32e3ba377f450",
      "${SDK}/usr/include/machine/limits.h": "50345f1ab843fca787a38c552a84177e678d79dab86e714434f94f2546839357",
      "${SDK}/usr/include/machine/param.h": "9a03a8edbbe2c4718553013b97dbac07113610350f983994aa53db0db07e0bb5",
      "${SDK}/usr/include/machine/signal.h": "09b1798034cf3b5217df3e415d6053df9c2e16b858036fc11888e63f4493f53f",
      "${SDK}/usr/include/machine/types.h": "76e7c59451d996fe674a6fc7e518366609a95875c9b9aec9fd590a3ac138dddd",
      "${SDK}/usr/include/malloc/_malloc.h": "582378b3f3074aa1aa831dd0c378d4dc71cfdd77d1840ca6291fca5a85f95abe",
      "${SDK}/usr/include/malloc/_malloc_type.h": "637f4e32fed7f9005738b465b124f388458270855001d68ec3ce92e643171cae",
      "${SDK}/usr/include/malloc/_ptrcheck.h": "d3c4e809117b24467e9313cc348c0495aad8780cea6bf58177743b9be09c3591",
      "${SDK}/usr/include/net/if.h": "a92c3d0f7af77d8865689a16e93dc0f90c3b7fb7a7b4a7bbd2640a179ea31ff6",
      "${SDK}/usr/include/net/if_var.h": "3ccf9bd6658d988d2bcd359772bcd529595d6de45a38b4355e8e7239c9b1905e",
      "${SDK}/usr/include/net/net_kev.h": "c12d7b438a9731b53538c405e68a94f3c851f4b5e1a7f6b9aea041ef9cfb64f1",
      "${SDK}/usr/include/net/route.h": "e93146e2f012b2cc4521a799f0381ef76a1543a9308ceb0dcf9f0d166c41bbf3",
      "${SDK}/usr/include/netinet/in.h": "e97c1992215250067fb553af2722633a240fdeb675e7560551e872b81a90e8bd",
      "${SDK}/usr/include/netinet/tcp.h": "9bd00e10a08b7315cf2b94de98e79c770c2ca81a84b3d80ed0bf169d542b7007",
      "${SDK}/usr/include/netinet6/in6.h": "0c5af27c35561b09b988f7eba5ace52de8f22fccfa62e3d1225fc666b2bf8119",
      "${SDK}/usr/include/os/availability.h": "620185ddfad2c157028a978ff08796a9c63aafe4e7c674921e9f0b8dda3a5092",
      "${SDK}/usr/include/os/base.h": "fe33fb653b1a5b5324806b747077bd9dc714c4f8478ab1775c3af49eddf1fa7e",
      "${SDK}/usr/include/poll.h": "dc10a7ff3e8952c80305a099fa247a572f636b5b8f9f6b82f7e6b7d999fc6af3",
      "${SDK}/usr/include/secure/_common.h": "b1d2144ca87b151923029abde3e69b2430f2b39304837e2183b9019fc50a6e96",
      "${SDK}/usr/include/secure/_stdio.h": "78633fd545a6a80e6e6c863e767936aed80009b92145e7db78c44441c71b92c3",
      "${SDK}/usr/include/secure/_string.h": "66ece2d83b7528b0eb85a1f82c8aab0465cbd074397ea1aa6155706a0244cc67",
      "${SDK}/usr/include/secure/_strings.h": "d635b58e48cb88db18226bab8a3588505d07dcae8820d2244902242f9406c65e",
      "${SDK}/usr/include/signal.h": "df78bfe0b6769e65ee187814d1f5eeb1bd87b6e7eeac96170b2ecfda231df3d0",
      "${SDK}/usr/include/spawn.h": "2d90f16beec60b2080553613234f004b58f384003feaa5eb809fe5e91b42b884",
      "${SDK}/usr/include/stddef.h": "1e871643e931a1fe9ba76c2cc55dd32aa1a4b4cdf4584901b65b6203db321d2b",
      "${SDK}/usr/include/stdint.h": "9d070aad02d9f2ba1f2248d093b4194b62cf8d363778c737d1110f4736e5ed3c",
      "${SDK}/usr/include/stdio.h": "d2220614f42d3cb678ae0de176ba0ab3256e15fb45b3efdb5d17b8ac1f6a4b54",
      "${SDK}/usr/include/stdlib.h": "7995a2df951dd1fdbd9fd4ec38900b79ef1797655ff239728fdbac56bb9bd7ff",
      "${SDK}/usr/include/string.h": "4b1b9c05bfe370d423d7a6bf9e74b189bcc7f59c1cd97f23d6d94f2f3df6a4bc",
      "${SDK}/usr/include/sys/__endian.h": "8697850f0ec13e9082081e9b8dda8f94053970f3546e4a8d42738b16400eac91",
      "${SDK}/usr/include/sys/_endian.h": "fcb57b694d555b2a8646e35bc68cc6864deecbc8d5528cd40bf764b1ff14d3fd",
      "${SDK}/usr/include/sys/_posix_availability.h": "452bff9ae32655a49b65802e29b21c67a546be1446553f908ef9850a694746bd",
      "${SDK}/usr/include/sys/_pthread/_pthread_attr_t.h": "987973d4e4f0c84a929fb1288755637453d88bf1410b778f81b2550ea4ad211c",
      "${SDK}/usr/include/sys/_pthread/_pthread_cond_t.h": "1f44e579de86408da3f83e47918e11d62d41fdce1c0230a7e30f5c56414ef914",
      "${SDK}/usr/include/sys/_pthread/_pthread_condattr_t.h": "167ad51c9e184c2f22e67dd7100e321305b11b3fe2cbeffd074015f20ce4e315",
      "${SDK}/usr/include/sys/_pthread/_pthread_key_t.h": "aa386e8d73d64c95432c42133e1ce1a0f4e6b5769a4720ad38c81c71355e12b9",
      "${SDK}/usr/include/sys/_pthread/_pthread_mutex_t.h": "9af87ec733f482f5bb59ff9c49b7884c6fd58444669fac8e64525da82f03cc91",
      "${SDK}/usr/include/sys/_pthread/_pthread_mutexattr_t.h": "93686494113a5167f198d6a586c1ac1c5f87eb0ef5751b9c441db52df0e9edd9",
      "${SDK}/usr/include/sys/_pthread/_pthread_once_t.h": "5ea5cc064b4770a6c776a0c84f9458f8089540a62244417de37309aa72c89fc9",
      "${SDK}/usr/include/sys/_pthread/_pthread_rwlock_t.h": "1e20731f227b6c0c83d149c9564bceaa62220128d81c04833abd835d469115c7",
      "${SDK}/usr/include/sys/_pthread/_pthread_rwlockattr_t.h": "f60fae1acfd6742846ffdd7a07a47996caab73ac12bb421b49a4aae3edb80d66",
      "${SDK}/usr/include/sys/_pthread/_pthread_t.h": "7bcef3e2436e7a96bf0201e99bad5a11e6d495dbac85b10207441c05d7fb461e",
      "${SDK}/usr/include/sys/_pthread/_pthread_types.h": "741433612525badf767d48b1924d4c7ba564ccc5c1bab5cb7045c238850fa86b",
      "${SDK}/usr/include/sys/_select.h": "23e013274b46f4eb46aae8492206ed2862ea6c998e28e793427f38a5e499bb6d",
      "${SDK}/usr/include/sys/_symbol_aliasing.h": "be0bd8cbed76094f86924f0e24c8bbf7b4f2020e95b480966cad14a5c1138ecd",
      "${SDK}/usr/include/sys/_types.h": "863c4f07045775002b63b7e616742d9f746e4a02da4441442d8fe1138bbd0ff9",
      "${SDK}/usr/include/sys/_types/_blkcnt_t.h": "3526cf25ca7734bf6bc945c9483727b8c1ab3fde5ad8fb23acad7489e231330d",
      "${SDK}/usr/include/sys/_types/_blksize_t.h": "4331ba446f9b5930e5da1dc065c97e258672ed0cbec5b3f0816c228fd0198955",
      "${SDK}/usr/include/sys/_types/_caddr_t.h": "de66a048df85e5fc79222edb89f9d73d63381c7076d0ec0bcdd41f23d0a01134",
      "${SDK}/usr/include/sys/_types/_clock_t.h": "e7be094e48f450875288ef68a59409e530dbe2d9449c78ff3d9ea9d654e0e857",
      "${SDK}/usr/include/sys/_types/_ct_rune_t.h": "17b8b91c92c4929111a4e854a38a04c3d07fe0da2a31f3692e1407db6a69de63",
      "${SDK}/usr/include/sys/_types/_dev_t.h": "4ba3d19759544b9f7bf424d2a16a518ff586e31ed968d525440e678cfbb07a5d",
      "${SDK}/usr/include/sys/_types/_errno_t.h": "ca230b22b22becab1bb191bfe5a8dd4595ea0566f5c8cc9b299eca308ee5a271",
      "${SDK}/usr/include/sys/_types/_fd_clr.h": "ccb785f37fdf5503df860a3fba82d8570a65f7ecbd754a5558254483b996747c",
      "${SDK}/usr/include/sys/_types/_fd_copy.h": "f4f4289b3da098621b7ed0115faa7d4b85b65852c4615c9bad5e222a8ceb0078",
      "${SDK}/usr/include/sys/_types/_fd_def.h": "feea8c758abe49372bcf3ab7dd9b0391d02269e4a531ef838895e961e9f43f30",
      "${SDK}/usr/include/sys/_types/_fd_isset.h": "17bdc86c26b6c82411601e955af5e2563a86f2fdd345568b78ab8642b895d1ae",
      "${SDK}/usr/include/sys/_types/_fd_set.h": "57009e7fed060e007604e0259788a7bea6afcb18fc4840fc30cd641f58655190",
      "${SDK}/usr/include/sys/_types/_fd_setsize.h": "7cd3a93f51f4521e60151c08b1fab36ea8efbb98988bb03db24264a1c434eaee",
      "${SDK}/usr/include/sys/_types/_fd_zero.h": "e5c44af3534182fe3b0872f39617ae17cd2ada72339e6f388eead5472df64c6f",
      "${SDK}/usr/include/sys/_types/_filesec_t.h": "d5f38f0f50dad1020edf0594798912b34922397a1be0cd33e71e565cd46cf44e",
      "${SDK}/usr/include/sys/_types/_fsblkcnt_t.h": "f986ed21599c2e0e1fc2efb8e014aae5a99e9f40d374a3e1af9b7c98ac9815cf",
      "${SDK}/usr/include/sys/_types/_fsfilcnt_t.h": "e56f6f9b9c48eb7c035d5241a611169cd130a6319a5d179522c818d9d3384cdb",
      "${SDK}/usr/include/sys/_types/_fsid_t.h": "63908a097cb2628d6d652317974e416a0df39e46b1a9a0ab0a10b83ea8948a2f",
      "${SDK}/usr/include/sys/_types/_fsobj_id_t.h": "f411229eb775e55326d5f3e1e00c822c97fff57e474e5f66574aa1572d67259f",
      "${SDK}/usr/include/sys/_types/_gid_t.h": "e687ad58c03701c132a02ebf20699c8cacfd34c3a67271bd2a415a5a8e4a9ea7",
      "${SDK}/usr/include/sys/_types/_graftdmg_un.h": "2ffe39c04264bcedad3742622786e181fc07e2c887a689143a7f926558b00ad1",
      "${SDK}/usr/include/sys/_types/_guid_t.h": "7fa1d7251dbc7160b64401e61ec841c0f70414976c8d65b9204887fc65e2c618",
      "${SDK}/usr/include/sys/_types/_id_t.h": "fb7255c9872e2a805c206796326e21d47146e22c93c09752126d7166bdaba5e5",
      "${SDK}/usr/include/sys/_types/_in_addr_t.h": "8da608117e441ff6e6b108d35334d7cf4b346b838522f97bcc621d925e0ba7fe",
      "${SDK}/usr/include/sys/_types/_in_port_t.h": "cf4b90c7af861346ee46c6b9e5d57cfe20bd62a03b1533ee9a369480ace0bac9",
      "${SDK}/usr/include/sys/_types/_ino64_t.h": "f143d5c0bfea65489ef89a866e96c9065d7ac28d62c0cec36f79d4dd7269fd13",
      "${SDK}/usr/include/sys/_types/_ino_t.h": "1e067108b372f2c81cfcad28413d6c0d2b9ef21d34fab740c3c8af059deadfea",
      "${SDK}/usr/include/sys/_types/_int16_t.h": "e40d40ad59c6dc98577b2c7cfdba1121ebfee17b29e093cbd10b7936df496d8e",
      "${SDK}/usr/include/sys/_types/_int32_t.h": "77127195e57f1690402377ddd72e3dcda684ddf591346f08ef4772dddcbbc281",
      "${SDK}/usr/include/sys/_types/_int64_t.h": "a2427b34e5e83996bd28d83cec920cf3b82a366af90e767234557bd11fa33a18",
      "${SDK}/usr/include/sys/_types/_int8_t.h": "607f6beede0251eb801e763493df26fd45d46eb951e4ff9cac17f1ac951b8cc0",
      "${SDK}/usr/include/sys/_types/_intptr_t.h": "b2a7ba9b9b2d357d75e59114874658f893b23ea6d1357815b027d8189075daba",
      "${SDK}/usr/include/sys/_types/_iovec_t.h": "f60cfdd101322d759ce291978284113a4e5a3f867cabecdcc66318a59c0f3884",
      "${SDK}/usr/include/sys/_types/_key_t.h": "42e8a3f076c5892d7b8ca5594b15a989eb206df5834070bd2b89b1febb3e9913",
      "${SDK}/usr/include/sys/_types/_mach_port_t.h": "8f178c4c396766f74c2cf8240af9ca420aef38b67bd0d6b7b1ec84c2c48dfc91",
      "${SDK}/usr/include/sys/_types/_mode_t.h": "7c4261bde41387fc23aefe5dee1e6298ae6b6f5592bca51947fdd9736e0640a6",
      "${SDK}/usr/include/sys/_types/_mount_t.h": "b2e3f4a4bc8f59a6a47e2907ec11a33fa3c406e1a55f81f8ec90ec15acc6b14b",
      "${SDK}/usr/include/sys/_types/_nlink_t.h": "7cc46bfc5d0f4238c735ff28bb1a8dcefc26d1f0e52b7098a5c89e68bf87288a",
      "${SDK}/usr/include/sys/_types/_null.h": "3e021525d2a711070e9c78ea2791e020ef6105c51121d8496d617f89a83d2f92",
      "${SDK}/usr/include/sys/_types/_o_dsync.h": "47e59afa1ca0d9beeb20835cbf44ea9d6dddc5bd12822ca35c5c0fc21dd45c49",
      "${SDK}/usr/include/sys/_types/_o_sync.h": "76de975c1a6a1c621851079934547a628665d15049a451dc6c7e2ddec779f1b0",
      "${SDK}/usr/include/sys/_types/_off_t.h": "7b07626d71084f1b3220e045089f54fd30f4d736be9cd0449042c5fe411fc569",
      "${SDK}/usr/include/sys/_types/_pid_t.h": "052a6dbbec8e30623c2d33dd373992f6c5d0c57c57ed4949d2b48c4ab0976487",
      "${SDK}/usr/include/sys/_types/_posix_vdisable.h": "f32872a8af4cfb71be9ca5bcd356241badadceba195d55907129425bc239c222",
      "${SDK}/usr/include/sys/_types/_rsize_t.h": "ac4928fae2b5d9d3728c1365c8e6552652cc22680158655151ddaf6a49ce795d",
      "${SDK}/usr/include/sys/_types/_rune_t.h": "36cd7e6c6ce34e125b4c52f005262d38eba8ef8486c7cac7adedcc5d37cc3b49",
      "${SDK}/usr/include/sys/_types/_s_ifmt.h": "95154f4d16869867b303c173ed569ab17957fedb98ce7140583df75bcca2bd9e",
      "${SDK}/usr/include/sys/_types/_sa_family_t.h": "04be200df47f1cc3e10ec0a57ac563b8ecbd80c3d29e10e8ea5875145c4d53b7",
      "${SDK}/usr/include/sys/_types/_seek_set.h": "353b2276ef8132f625b1b780e7593a43183fbf054c1bc906c0515f89dad335c8",
      "${SDK}/usr/include/sys/_types/_sigaltstack.h": "2bc87d34186fe6524fe89fa1e2d878462c6688134d03880b8bfa1486db297687",
      "${SDK}/usr/include/sys/_types/_sigset_t.h": "df99c73ecdbde1fcb3a4a22169871e036240452472b8ea70f287456d42593972",
      "${SDK}/usr/include/sys/_types/_size_t.h": "3e1bcf6c23ad00e0fe2b5a4683e687299baf51cf26b0a4ebc73db6140378acc2",
      "${SDK}/usr/include/sys/_types/_socklen_t.h": "a747e7fd8c243c7bbbd2f2cfa4b05f56f905e1f013fb2ff230f07a1954fdbf07",
      "${SDK}/usr/include/sys/_types/_ssize_t.h": "58eb3bdea24b27e6b5fb45e203e476faf2510b5c0aa81a0b45c17b528aa9c192",
      "${SDK}/usr/include/sys/_types/_suseconds_t.h": "d799ffc16cf29b6559b36d879fc7d5fec80ec3c39502eaef078ae9178eeaf275",
      "${SDK}/usr/include/sys/_types/_time_t.h": "c0a28cdc5c9c8cf99abea53556895bd8001a6cb13ae6ca9f366955500678b35a",
      "${SDK}/usr/include/sys/_types/_timespec.h": "3314f260a6b3ce09c02df185ba2253577b2a268dac05d3cad55f76bb3e8019e8",
      "${SDK}/usr/include/sys/_types/_timeval.h": "f723018fec267200e915777897515b5d7ed20901bcb294873f94b1d835f9ae45",
      "${SDK}/usr/include/sys/_types/_timeval32.h": "5d80e8bf5f32db57d31158140f8bfe6b57f2720c89591d1bee3e0bb789a75026",
      "${SDK}/usr/include/sys/_types/_timeval64.h": "76ac085edf939eac51da6b4a605f42ac3b97e9ea69c6f4935a7c5b3c70721226",
      "${SDK}/usr/include/sys/_types/_u_char.h": "50e11dbb6152079cdefd9eaf854e3182496130b651142e0fc08fcd1456802e81",
      "${SDK}/usr/include/sys/_types/_u_int.h": "85e9858c13fdc4fb614948fbcadec5f5973dbf6874b97464044a3b4e23486978",
      "${SDK}/usr/include/sys/_types/_u_int16_t.h": "9dabbd8280c28416a5ba115355678d2540588df1a7251bd9b4a13e30c309a71b",
      "${SDK}/usr/include/sys/_types/_u_int32_t.h": "196cba7a865c086bba457758d3b2605a4c1299c54a758366b7d420a585895f1d",
      "${SDK}/usr/include/sys/_types/_u_int64_t.h": "d096eee54a5acc2c3cd5cf71256d69198ada8f8d82cdb0a717bc8ed65650ad93",
      "${SDK}/usr/include/sys/_types/_u_int8_t.h": "7505dbbdf3ecca2b8e585871ad81c0e67a3cb63c97c47abe73fe262e071a3ebb",
      "${SDK}/usr/include/sys/_types/_u_short.h": "f78b1ac66a04e293df9a08ce2466401f50075a773c5f64000864b9d59ec4edc9",
      "${SDK}/usr/include/sys/_types/_ucontext.h": "d67fecbd5fba1fc876b41b0a69ff080e3d47c9884f3ea4012f8a334ffda62681",
      "${SDK}/usr/include/sys/_types/_uid_t.h": "d2140a65a17943a857381757c0b73a920f35ade41dc9809437c168be457c276a",
      "${SDK}/usr/include/sys/_types/_uintptr_t.h": "f435cf25e4f06dace9c1884c066392bafd204c6d71f16696e71acde5912bc81f",
      "${SDK}/usr/include/sys/_types/_useconds_t.h": "37c49808a92cc4417181adb1530cc24ca11cc89f064c6c0494a1aff981f92870",
      "${SDK}/usr/include/sys/_types/_uuid_t.h": "ba8364ff4aed847f5ca3259e27fc2d1920432d02e8e79c7ac57ec043f1dc2842",
      "${SDK}/usr/include/sys/_types/_va_list.h": "688c84ca73e82898609ae7282c820e896e4b82b7dc14f4fc92b4263df5827de2",
      "${SDK}/usr/include/sys/_types/_vnode_t.h": "334e00e29a707f060907cb9f6c946dd9f0dc7102ab9a7c7986ff6f1c670c51ed",
      "${SDK}/usr/include/sys/_types/_wchar_t.h": "f0c3da0beecb5feb19ddede0ea9d5fbb9274e7b1de1b7cb91f64196ac1395008",
      "${SDK}/usr/include/sys/acl.h": "9511f84f0abe1e108e10979900d4fea8567534aef78f0984f7050c49f6c29ff7",
      "${SDK}/usr/include/sys/appleapiopts.h": "efd9793f56c08917cf1ddf5108b78240ede88a5bbc8977d6fdaf1684b6b01c1c",
      "${SDK}/usr/include/sys/attr.h": "5118b9245bc932bc32dcc60084b1e40d70bb5479a360b31cdbf188ef866deefe",
      "${SDK}/usr/include/sys/cdefs.h": "ac1a889ee7e6f3025e01be9981d26751489b9e63e926035201cae07ab9e6576f",
      "${SDK}/usr/include/sys/constrained_ctypes.h": "8abf801e1866096c72098f75984aa907f32080445657778ac81349ec2b55f9e3",
      "${SDK}/usr/include/sys/errno.h": "109ace10e79b9467dee3b8c7890f1d5bea1102d982c521922e9d372ab9863c97",
      "${SDK}/usr/include/sys/event.h": "435ed8fe99ae70c19404c3da14be6e2d217686ac256aed3b5df721b353dbb350",
      "${SDK}/usr/include/sys/fcntl.h": "9aca8ca87031ab7b670617e5af8b15a0cad8f34f7ab3bdb5dd799eb153b3ad0e",
      "${SDK}/usr/include/sys/file.h": "51ce3d051280d73d96a022f944ed6eb60be2db91322a8a951c4ba1ae823fc667",
      "${SDK}/usr/include/sys/kauth.h": "9c8808c918bb6fb8c4f9854f7c34d7d51b2017de8e19f4bfc67cf82b7553d0b4",
      "${SDK}/usr/include/sys/kern_control.h": "84fc7642ed79b041667f9f1ac3bdea1d8abfaa194117ca4ed40b80f2d9dc7cdf",
      "${SDK}/usr/include/sys/lock.h": "6141dbbfc071934b24ce23dcfe52def2b0d34d6af60a6a21a0c9d96d7461f339",
      "${SDK}/usr/include/sys/mount.h": "45872741bb916b92bddd2e562d2047b552af1f68269081a0aeb58a3e5a2b8a51",
      "${SDK}/usr/include/sys/param.h": "10d7a9553d341c5bc0b473444802920a7ec2e6222281eeaeb61b32dfff29c4b4",
      "${SDK}/usr/include/sys/poll.h": "809417bb85e700534f8f1a426b4e70f4b0bce0747199ba9f2e7d93b071aaeac9",
      "${SDK}/usr/include/sys/proc.h": "593af71b2740ba6248995691280bcb15f8900d46b1d9868f7345084aa0692949",
      "${SDK}/usr/include/sys/proc_info.h": "e427fa96b348537b21552b9de71e01039410bcad2cedee5584c5e5fddafd70fc",
      "${SDK}/usr/include/sys/queue.h": "70dd22988c82ae2ca344277d073b6189b4875b92905a687ab75cfc4c983fe029",
      "${SDK}/usr/include/sys/resource.h": "1067178025c5fd88c9a1b8206a07c2695ef94dd471fe2783f06c512995382961",
      "${SDK}/usr/include/sys/select.h": "cffe3e51c7c6c6ef68750cc85f7ddc1b7b4be041a4bbb47fd19914125bf1b6df",
      "${SDK}/usr/include/sys/signal.h": "46001a703a66591b9adc873dcdfe4a545bb26cd5fc52b31ede9e0cda9ddbac7a",
      "${SDK}/usr/include/sys/socket.h": "14405cbcbbdf72944e0425f95e5f3627b534f25eefd0e93ba9544a31c9f85cd7",
      "${SDK}/usr/include/sys/spawn.h": "988afa3a6d7a1ce18df118d234240c02eff0715b5712784ac28b44e7f66254dc",
      "${SDK}/usr/include/sys/stat.h": "1546ce7485287bec0d15a643ef5d5f882d21272f2f089fed71c36457e609b92a",
      "${SDK}/usr/include/sys/stdio.h": "a8078ae1cba1a46a66d0de6fe7f13bbc969cdb7e78fc2d4b9a5c5cdaaf16126b",
      "${SDK}/usr/include/sys/sysctl.h": "d6d627d3353607f4078079051e09ea0e9a3b32a6771934be1ac5d89fbe93b1c7",
      "${SDK}/usr/include/sys/syslimits.h": "170629c923b4ef2b7132dc8a9d71e9f010332bada56363f619b7c758e17d2c83",
      "${SDK}/usr/include/sys/time.h": "89da128487ce75eca6f6bd40453d7ed8e25f583cdcdddb97bf297efac75846d2",
      "${SDK}/usr/include/sys/types.h": "82111e1f1d0262bee191b4679842e5ff51de57310ce4da9f48d39af0d8e10284",
      "${SDK}/usr/include/sys/ucred.h": "58770070750d6fd96d41a3e32efc36fa23afd268eef23c8ea3816df38e1bfd0e",
      "${SDK}/usr/include/sys/un.h": "a733cb89955ef81312f4bc3a42002c6cc873e27381eb43656c7158ef9a433c24",
      "${SDK}/usr/include/sys/unistd.h": "4f0463cea7c466850593f10341e9d57757f8570f610cfa748b5c6a3925842b76",
      "${SDK}/usr/include/sys/utsname.h": "2d51c76d8c2448b0402aa92296747b4619b1956a3b98eeaf16875a40099a6b0e",
      "${SDK}/usr/include/sys/vm.h": "b35738bc54a422da2db724124a3059ce9b5e97fe3e62c3188762301ff1b1288c",
      "${SDK}/usr/include/sys/wait.h": "59742f1ebee76c58ce7c36a44f4ee7cbf4faa6edfaad7a32208190e193d76bf6",
      "${SDK}/usr/include/time.h": "cf4912303943c5bda8404f5fd7a2a8219153353a49df2aeaddbb2dcd4b35c0bf",
      "${SDK}/usr/include/unistd.h": "8d535079658f063bcef358ef4c1c1b52b8e88dacfc22cbf4db0f6bf8abe40637",
      "${SDK}/usr/include/uuid/uuid.h": "720615541b88718ca8eb98acecf70d6d0e5f3d9d0bbd01e136fdeda680ceddc1",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_header_macro.h": "4cf46e8fbb809df048eecbbd63686fa741da27afa8db4245bd1f61c1fb1611dc",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_max_align_t.h": "3c1e4de47f4f06b35e2c5890d670052e84f716760505ff51b022fc8b21a9400f",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_null.h": "b1d71b08563ab3d2c22a1e4f8ddf4d9a1111c89e9404b859a45c307e8ebc6c69",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_offsetof.h": "e5f0f4ff8ff5fc6a1cc8b535f5065f1728eadd2bf1e1401f021f803ec7b4222f",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_ptrdiff_t.h": "b4178a57f3711b7013cba747a72a2f178c29fa9364e77d75b2159754072ced43",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_rsize_t.h": "132339d4f07e852bf2d879bc91c4ccdfcf08c581c7c97f6f3794510e0bdda7bd",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_size_t.h": "d86ddc0238da09b385846ebef814ffc50a44e40cf85d4e3793f485952b7e73ad",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/__stddef_wchar_t.h": "1900d4998aef3698b06399ed686db0c21e26509b08638a25734fb97ae89b1001",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/limits.h": "6b59cc1b6f86c901bf41ce942b8434530e852eb16e79e6e9287f89441f71efca",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/ptrcheck.h": "ac60d1e96ac17d789d1879b968d391dfbfa222f12213ba95f14592453eebe338",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/stdbool.h": "48655faf4ebd4ca0af26a1ee8e3e16f8dc68385c9cd550ffb3629320681305b3",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/stddef.h": "e8d92dad1b380f2f2130fd7aa446bcb4fc923f7062a41c7c35beb4913093a8f5",
      "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/21/include/stdint.h": "f43783466c93f77a6464274ebf18f9e4cc46f0d90770ddee2993c6cf39f7514f"
    },
    "rows": [
      {
        "dependencies_sha256": "612df726bd38128cb88647321a0a576f8d1d076b78e953bc1e251a816ed676ca",
        "dependency_count": 182,
        "depfile_sha256": "5a6dfc79ae0e6563ad089622733bf86cbd5dee0261179a13739af9b4e87e1ae1",
        "output": "CMakeFiles/bee_hermes_a2a.dir/launch_authority.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/launch_authority.c",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/launch_authority.h"
        ]
      },
      {
        "dependencies_sha256": "536e388a698dff257f0daa84d5ff51e6b2ed77876f20b848a3c691e22f737d30",
        "dependency_count": 166,
        "depfile_sha256": "d04779c157f25c8726c519e49b99bf1a2441b5424c6969328b028bd71357c2a4",
        "output": "CMakeFiles/bee_hermes_a2a.dir/stage0.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/stage0.c",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "845319c157ed932d8ec6c88e88de67ae123990204c7116bf6b12ae08eaf862fc",
        "dependency_count": 145,
        "depfile_sha256": "34498a129f5a409e535b14f606c61e37cde8521f39ebdec3ee34130576259992",
        "output": "CMakeFiles/bee_hermes_a2a.dir/release_manifest.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/release_manifest.c",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "3539b66747aee9bcc7e3a47effee7dec75877cf4402f83dd6d8f81e7af0e2514",
        "dependency_count": 225,
        "depfile_sha256": "2b9652a9d17fb65235a313debf17e2e0200d1027b31cb7e8c38a8e3f56229c09",
        "output": "CMakeFiles/bee_hermes_a2a.dir/fd_inventory.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/fd_inventory.c",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "fcbf6b5ac1e7afeb102766d28e3b76aaf38bf22044f35cb3dd258b4a2996e773",
        "dependency_count": 177,
        "depfile_sha256": "f4221263183aa3267224d3d658802167674ba4528a13709a45952d6d74308c2b",
        "output": "CMakeFiles/bee_hermes_a2a.dir/socket_lineage.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/socket_lineage.c",
          "native/darwin_bootstrap/abi_v1.h",
          "native/trusted_inbound/darwin/socket_observer.h"
        ]
      },
      {
        "dependencies_sha256": "c9abd33d57cbd974151f8b43afd3489e41b539959785171686655528eb7116d0",
        "dependency_count": 205,
        "depfile_sha256": "60ef2bce7a81c1ac869b6a93497a8aeae96be6073af1e2e9bd69d34712e8ab3b",
        "output": "CMakeFiles/bee_hermes_a2a.dir${SOURCE}/native/trusted_inbound/darwin/socket_observer.c.o",
        "workspace_paths": [
          "native/trusted_inbound/darwin/socket_observer.c",
          "native/trusted_inbound/darwin/socket_observer.h"
        ]
      },
      {
        "dependencies_sha256": "9aadfbc8adbd8c8fccbe9288a888463f6ab608528787504157029335207a0561",
        "dependency_count": 211,
        "depfile_sha256": "127a0113fbc496208863f4aa34138517bd57dba05e34c03ce0321ccc4d5420db",
        "output": "CMakeFiles/bee_hermes_a2b_fd7.dir/broker_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/broker_entry.c",
          "native/darwin_bootstrap/broker_entry.h"
        ]
      },
      {
        "dependencies_sha256": "74f9e8e46d7f7bda2fa52ed1423468df25b1e6dd5b48c56dcf7a65a8a2b06fb1",
        "dependency_count": 164,
        "depfile_sha256": "8d9eae2ac6cb68040d9720a8b0abd0ed94628a0a85ec08e6b6c06d43dc2dfa49",
        "output": "CMakeFiles/bee_hermes_a2c_phase1.dir/a2c_policy.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_policy.c",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "2704433d55bf9d018046da4fa6acde67e338d9ed9708981dd8fcbec4dd7d99c0",
        "dependency_count": 212,
        "depfile_sha256": "59682cfc1bd2c161d846a8cdc8eb8d9ba318a7c00b2f3fb7ae76bf147de401b3",
        "output": "CMakeFiles/bee_hermes_a2c_phase1.dir/launch_control.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/launch_control.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "43b7130f76fb14ac3121e53abc9354793fc283f164a4bc4fcaeb09eaa8e9b281",
        "dependency_count": 177,
        "depfile_sha256": "4cef75106242d72dde69a2a7cff95a2de9efae30900c6c3ae5aaa25e0702beb6",
        "output": "CMakeFiles/bee_hermes_a2c_attempt.dir/attempt_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/attempt_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "bc5e8cfe5b470b291a0f323a2712454eef44d72658845f33acdfccf1704b25e9",
        "dependency_count": 164,
        "depfile_sha256": "a0c8808305bfa25fb73a66c83f0039ca07a63a9ac8fa0f7645fc1d4c28a73ff8",
        "output": "CMakeFiles/bee_hermes_a2c_final.dir/final_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/final_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "53f6276a3445e35950272665fd1260eae01ac17a35b34ee622f5e3f55e2e948f",
        "dependency_count": 155,
        "depfile_sha256": "2bd58cc25c0d72a591a9c0f55257991d08d4924cf91b173f871e81b8eb7e8213",
        "output": "CMakeFiles/bee_hermes_a2c_stage0.dir/stage0_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/stage0_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "43b7130f76fb14ac3121e53abc9354793fc283f164a4bc4fcaeb09eaa8e9b281",
        "dependency_count": 177,
        "depfile_sha256": "b8be35045c78ab2549c845beb4b7603467b5dba50a9b97b6a84bd7d6ed5c3d43",
        "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/attempt_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/attempt_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "603727bc4b5d13cc6b481547928afd455908d58ad841a947802b457ecd94e5b7",
        "dependency_count": 213,
        "depfile_sha256": "60ed8ab47fd44fa8aa29c0c1053d12994ac513892d931c6aad36148baa81974b",
        "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/launch_control.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/launch_control.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "74f9e8e46d7f7bda2fa52ed1423468df25b1e6dd5b48c56dcf7a65a8a2b06fb1",
        "dependency_count": 164,
        "depfile_sha256": "5597edce2dad4a07e530a9aa5678978c77bf5450489a3da5e2df5c243f8d5ed8",
        "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/a2c_policy.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_policy.c",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "f735c6cd38b7442010afebef5bb38d6a18b6f01db329e96cc8c2b87dd095848e",
        "dependency_count": 168,
        "depfile_sha256": "ff8d1d8206562f6cea443ed3ff480924ec8039dcc3296e14388a1bf91076a18b",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/final_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/final_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/a2c_phase3_io.h"
        ]
      },
      {
        "dependencies_sha256": "e2b7809585d3f953ebb076919a04a6bba3257d83c55464bc08e3970d75692deb",
        "dependency_count": 148,
        "depfile_sha256": "fd694bd849311a056cdaf3ae36e20060861df5cb305544c8b12d017094ce7e28",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_policy.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_policy.c",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/launch_authority.h",
          "native/darwin_bootstrap/a2c_policy.h"
        ]
      },
      {
        "dependencies_sha256": "9ad1cd51a3ef158bd734a419de827249338223e71656c199e63c1a83a6865220",
        "dependency_count": 172,
        "depfile_sha256": "4b53efc317e7e507ec1cb652e5f9402987b8ec3fedc93327da9ffeff1535e91c",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_io.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_io.c",
          "native/darwin_bootstrap/a2c_phase3_io.h",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "0e6630685935f20e0caf20e0856e6f98600a894d90137bd4d081683d756c3bb7",
        "dependency_count": 139,
        "depfile_sha256": "c7c2bce89cd3486cd32fa0b5bbdc9a6520516734a5c94ceb2b92135071933d02",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_unavailable.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_unavailable.c",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "53f6276a3445e35950272665fd1260eae01ac17a35b34ee622f5e3f55e2e948f",
        "dependency_count": 155,
        "depfile_sha256": "77747490e99f7d35983329d80a962b535388bb9a33a174320eddb75b169cf3de",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_stage0.dir/stage0_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/stage0_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "5c071744023b658104a995d06476358f14003504e643a4cf3d60a53ab8a1da16",
        "dependency_count": 178,
        "depfile_sha256": "2c716f7ebffe97d60ce72d251acc81bacaf1a9b5e31e65eb111d8f4823ad1b53",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/attempt_entry.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/attempt_entry.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/a2c_phase3_policy.h"
        ]
      },
      {
        "dependencies_sha256": "64ae055b29a0bb1072fae93dab060c9409dc579766464346728b087ec43c4ee7",
        "dependency_count": 223,
        "depfile_sha256": "031779f8d149ccebce8d50efa20d7d8ccacb47291116bae336a8b9bdbebfa74d",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/launch_control.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/launch_control.c",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/a2c_phase3_io.h",
          "native/darwin_bootstrap/launch_authority.h"
        ]
      },
      {
        "dependencies_sha256": "74f9e8e46d7f7bda2fa52ed1423468df25b1e6dd5b48c56dcf7a65a8a2b06fb1",
        "dependency_count": 164,
        "depfile_sha256": "53d3dd77874c2b7d31467ae9696ec313b844e0b3304444c687cf6b3e3feca5b5",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_policy.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_policy.c",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "e2b7809585d3f953ebb076919a04a6bba3257d83c55464bc08e3970d75692deb",
        "dependency_count": 148,
        "depfile_sha256": "89afef1854ac89425a3497ee92773d72af657e912e6c4a36fce4d26bfa75e2fa",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_policy.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_policy.c",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/abi_v1.h",
          "native/darwin_bootstrap/launch_authority.h",
          "native/darwin_bootstrap/a2c_policy.h"
        ]
      },
      {
        "dependencies_sha256": "d665535358049d665db57bf43c00933685ea5652a7dd9f3e153ec87ed0f0ac00",
        "dependency_count": 164,
        "depfile_sha256": "6da381afde29d870fcfd097afe20b5e8836422be8fb5457b2e01610b24f7ca80",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_journal.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_journal.c",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "9ad1cd51a3ef158bd734a419de827249338223e71656c199e63c1a83a6865220",
        "dependency_count": 172,
        "depfile_sha256": "4a96f9f05b7f66b75c1f9a27b34d2ece113f99fa8c0e5f311ebe8170cade60f1",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_io.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_io.c",
          "native/darwin_bootstrap/a2c_phase3_io.h",
          "native/darwin_bootstrap/launch_control.h",
          "native/darwin_bootstrap/a2c_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "0e6630685935f20e0caf20e0856e6f98600a894d90137bd4d081683d756c3bb7",
        "dependency_count": 139,
        "depfile_sha256": "64755fd07a7c4dc04b1db39996ee0d1d5a111a1216caf0d7fd7860f85df7a8bc",
        "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_unavailable.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/a2c_phase3_unavailable.c",
          "native/darwin_bootstrap/a2c_phase3_policy.h",
          "native/darwin_bootstrap/abi_v1.h"
        ]
      },
      {
        "dependencies_sha256": "71981242ad3e1ff6ae41a9af41e2772135ea2b6b1bd7b97a9a616e61dae82857",
        "dependency_count": 59,
        "depfile_sha256": "f97a024c5990e492bd6ec6e03db459137a6202c4e026560205854a3910f352dd",
        "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_main.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/install_preflight_main.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "0de3f8f1ecce6434e27d10e5da2dc45a5415da8f1ac7d2dd6449562453922266",
        "dependency_count": 57,
        "depfile_sha256": "042005be71e9c3fb5da87df5965a4130aafdcfab9e589bb6a54901cd7719aade",
        "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/install_preflight.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "546d79ff5a695e00f319e296931c470c5bb9ec27615140d39642313eaa9ab005",
        "dependency_count": 34,
        "depfile_sha256": "600aed548c280cc25d42799bc7358ed92e9ffd7e1733e9c68c96ca0d03cb0a32",
        "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_unavailable.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/install_preflight_unavailable.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "c6f7a19c21868f96e82bf43114ef1197b9f703df66a34969b9781fca502ea453",
        "dependency_count": 66,
        "depfile_sha256": "ed40f41719a89b67591c12de9a9e8b315ae5731b128dc9bed94b7d18ff746ebe",
        "output": "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c.o",
        "workspace_paths": [
          "tests/native/darwin_bootstrap/test_install_preflight.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "ac9b8d93e4878a9dd57e5fd3f8269ed2fcfd4b5ad30dfb9fb9dd58b03bfcde94",
        "dependency_count": 57,
        "depfile_sha256": "a53cdea4bc7da1713cbeb1dab717d7ac572e425e9a1dd5923a3f46a2cf4d988a",
        "output": "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c.o",
        "workspace_paths": [
          "tests/native/darwin_bootstrap/test_install_preflight_adapter.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "0de3f8f1ecce6434e27d10e5da2dc45a5415da8f1ac7d2dd6449562453922266",
        "dependency_count": 57,
        "depfile_sha256": "8e3cd3cee2a243413370ab90bfbfe76045ab80b21ae6a28f10bd9d80fad701d2",
        "output": "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/install_preflight.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "546d79ff5a695e00f319e296931c470c5bb9ec27615140d39642313eaa9ab005",
        "dependency_count": 34,
        "depfile_sha256": "72b6387f719fe44b838519e2b8cb0493707c5fd587345eebaa47f7e614681ba1",
        "output": "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight_unavailable.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/install_preflight_unavailable.c",
          "native/darwin_bootstrap/install_preflight.h"
        ]
      },
      {
        "dependencies_sha256": "6c61b5e2c9c2ce949c535e53bd4c8881991c34fb886885cc5d834ee1081c19a1",
        "dependency_count": 80,
        "depfile_sha256": "ce535da101a118b3af5723dbd4192b0fff74a2975810deb3ed17d2c5f8b7f8bd",
        "output": "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/path_observer_core_v1.c",
          "native/darwin_bootstrap/path_observer_v1.h",
          "native/darwin_bootstrap/path_observer_os_v1.h"
        ]
      },
      {
        "dependencies_sha256": "08865110cc3b4b46b577ee1c1db3feac5c55a5497b145656eb84dcc17a7ddbe3",
        "dependency_count": 82,
        "depfile_sha256": "d0f470e71901af21f24410cafd855610ae1d5d8ad6cb2366fde87d6119cd491d",
        "output": "CMakeFiles/bee_hermes_path_observer_v1.dir/path_observer_os_darwin_v1.c.o",
        "workspace_paths": [
          "native/darwin_bootstrap/path_observer_os_darwin_v1.c",
          "native/darwin_bootstrap/path_observer_os_v1.h"
        ]
      },
      {
        "dependencies_sha256": "360bf5f26718c60df67910043fdbf06d3cb43ec0f297b8d56eee20a92d8b82fd",
        "dependency_count": 138,
        "depfile_sha256": "7146daaf973d875416648b0d676f5911a617c76b6a1a1d123a1e1806dbb8f8e5",
        "output": "CMakeFiles/bee_hermes_path_observer_v1_real_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c.o",
        "workspace_paths": [
          "tests/native/darwin_bootstrap/test_path_observer_real.c",
          "native/darwin_bootstrap/path_observer_v1.h"
        ]
      },
      {
        "dependencies_sha256": "23bd1f9c9e29c648eb692931095a606fe96803d7cc5341fd3ec76328e9a1e1d0",
        "dependency_count": 173,
        "depfile_sha256": "fe046e113baf2ab170b0e52e7f3d4b9855fe5a7348c03788e50d5c01c0a2ff6c",
        "output": "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c.o",
        "workspace_paths": [
          "tests/native/darwin_bootstrap/test_path_observer_injected.c",
          "native/darwin_bootstrap/path_observer_v1.h"
        ]
      },
      {
        "dependencies_sha256": "c5ead73c579ed5b758485c4abd23810dc3da5138a64bc37a7e66b4260223a19b",
        "dependency_count": 104,
        "depfile_sha256": "5bcf0811effcff4c4d1aceac50494cfc14cc1dfb3c22c52e78b8c8134891e1cc",
        "output": "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c.o",
        "workspace_paths": [
          "tests/native/darwin_bootstrap/path_observer_os_test_v1.c",
          "native/darwin_bootstrap/path_observer_os_v1.h"
        ]
      }
    ],
    "workspace_paths": [
      "native/darwin_bootstrap/a2c_phase3_io.c",
      "native/darwin_bootstrap/a2c_phase3_io.h",
      "native/darwin_bootstrap/a2c_phase3_journal.c",
      "native/darwin_bootstrap/a2c_phase3_policy.c",
      "native/darwin_bootstrap/a2c_phase3_policy.h",
      "native/darwin_bootstrap/a2c_phase3_unavailable.c",
      "native/darwin_bootstrap/a2c_policy.c",
      "native/darwin_bootstrap/a2c_policy.h",
      "native/darwin_bootstrap/abi_v1.h",
      "native/darwin_bootstrap/attempt_entry.c",
      "native/darwin_bootstrap/broker_entry.c",
      "native/darwin_bootstrap/broker_entry.h",
      "native/darwin_bootstrap/fd_inventory.c",
      "native/darwin_bootstrap/final_entry.c",
      "native/darwin_bootstrap/install_preflight.c",
      "native/darwin_bootstrap/install_preflight.h",
      "native/darwin_bootstrap/install_preflight_main.c",
      "native/darwin_bootstrap/install_preflight_unavailable.c",
      "native/darwin_bootstrap/launch_authority.c",
      "native/darwin_bootstrap/launch_authority.h",
      "native/darwin_bootstrap/launch_control.c",
      "native/darwin_bootstrap/launch_control.h",
      "native/darwin_bootstrap/path_observer_core_v1.c",
      "native/darwin_bootstrap/path_observer_os_darwin_v1.c",
      "native/darwin_bootstrap/path_observer_os_v1.h",
      "native/darwin_bootstrap/path_observer_v1.h",
      "native/darwin_bootstrap/release_manifest.c",
      "native/darwin_bootstrap/socket_lineage.c",
      "native/darwin_bootstrap/stage0.c",
      "native/darwin_bootstrap/stage0_entry.c",
      "native/trusted_inbound/darwin/socket_observer.c",
      "native/trusted_inbound/darwin/socket_observer.h",
      "tests/native/darwin_bootstrap/path_observer_os_test_v1.c",
      "tests/native/darwin_bootstrap/test_install_preflight.c",
      "tests/native/darwin_bootstrap/test_install_preflight_adapter.c",
      "tests/native/darwin_bootstrap/test_path_observer_injected.c",
      "tests/native/darwin_bootstrap/test_path_observer_real.c"
    ]
  },
  "manifest": [
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir/launch_authority.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/launch_authority.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/launch_authority.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir/launch_authority.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir/stage0.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/stage0.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/stage0.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir/stage0.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir/release_manifest.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/release_manifest.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/release_manifest.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir/release_manifest.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir/fd_inventory.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/fd_inventory.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/fd_inventory.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir/fd_inventory.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir/socket_lineage.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/socket_lineage.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/socket_lineage.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir/socket_lineage.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2a.dir${SOURCE}/native/trusted_inbound/darwin/socket_observer.c.o",
        "-c",
        "${SOURCE}/native/trusted_inbound/darwin/socket_observer.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/trusted_inbound/darwin/socket_observer.c",
      "output": "CMakeFiles/bee_hermes_a2a.dir${SOURCE}/native/trusted_inbound/darwin/socket_observer.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2b_fd7.dir/broker_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/broker_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/broker_entry.c",
      "output": "CMakeFiles/bee_hermes_a2b_fd7.dir/broker_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase1.dir/a2c_policy.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_policy.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_policy.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase1.dir/a2c_policy.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase1.dir/launch_control.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/launch_control.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/launch_control.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase1.dir/launch_control.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_attempt.dir/attempt_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/attempt_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/attempt_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_attempt.dir/attempt_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_final.dir/final_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/final_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/final_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_final.dir/final_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_FINAL_IMAGE=\"${BUILD}/bee_hermes_a2c_final\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_stage0.dir/stage0_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/stage0_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/stage0_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_stage0.dir/stage0_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE2",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/attempt_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/attempt_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/attempt_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/attempt_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE2",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/launch_control.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/launch_control.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/launch_control.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/launch_control.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE2",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/a2c_policy.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_policy.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_policy.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase2_attempt.dir/a2c_policy.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/final_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/final_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/final_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/final_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_policy.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_policy.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_policy.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_policy.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_io.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_io.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_io.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_io.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_unavailable.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_unavailable.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_unavailable.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_unavailable.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_FINAL_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_final\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_stage0.dir/stage0_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/stage0_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/stage0_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_stage0.dir/stage0_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/attempt_entry.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/attempt_entry.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/attempt_entry.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/attempt_entry.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/launch_control.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/launch_control.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/launch_control.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/launch_control.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_policy.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_policy.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_policy.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_policy.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_policy.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_policy.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_policy.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_policy.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_journal.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_journal.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_journal.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_journal.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_io.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_io.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_io.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_io.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-DBH_A2C_PHASE3",
        "-DBH_A2C_STAGE0_IMAGE=\"${BUILD}/bee_hermes_a2c_phase3_stage0\"",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_unavailable.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/a2c_phase3_unavailable.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/a2c_phase3_unavailable.c",
      "output": "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_unavailable.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_main.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/install_preflight_main.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/install_preflight_main.c",
      "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_main.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/install_preflight.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/install_preflight.c",
      "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_unavailable.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/install_preflight_unavailable.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/install_preflight_unavailable.c",
      "output": "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_unavailable.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c.o",
        "-c",
        "${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c",
      "output": "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c.o",
        "-c",
        "${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c",
      "output": "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/install_preflight.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/install_preflight.c",
      "output": "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight_unavailable.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/install_preflight_unavailable.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/install_preflight_unavailable.c",
      "output": "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight_unavailable.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/path_observer_core_v1.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/path_observer_core_v1.c",
      "output": "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_path_observer_v1.dir/path_observer_os_darwin_v1.c.o",
        "-c",
        "${SOURCE}/native/darwin_bootstrap/path_observer_os_darwin_v1.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/native/darwin_bootstrap/path_observer_os_darwin_v1.c",
      "output": "CMakeFiles/bee_hermes_path_observer_v1.dir/path_observer_os_darwin_v1.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_path_observer_v1_real_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c.o",
        "-c",
        "${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c",
      "output": "CMakeFiles/bee_hermes_path_observer_v1_real_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c.o",
        "-c",
        "${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c",
      "output": "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c.o"
    },
    {
      "argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-I${SOURCE}/native/darwin_bootstrap",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-o",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c.o",
        "-c",
        "${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c"
      ],
      "directory": "${BUILD}",
      "file": "${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c",
      "output": "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c.o"
    }
  ],
  "schema": 1,
  "sdk_inputs": {
    "aliases": {
      "${SDK}/usr/lib/libSystem.tbd": "libSystem.B.tbd"
    },
    "files": {
      "${SDK}/SDKSettings.json": "7b93ad7e534cc4b31c6a4e39d19b5e0288acf2168c2649479a796d1cb51939fb",
      "${SDK}/usr/lib/libSystem.B.tbd": "01089e97e7372fdda64ef480f2c99d483daf0c7fc99298a137425ee3230588ab",
      "${SDK}/usr/lib/system/libcommonCrypto.tbd": "ef1063b094e3b03e9c0ba0b6d4e2bb09f917a63104081ab3f5bff75d47a50649",
      "${SDK}/usr/lib/system/libcompiler_rt.tbd": "4c09714745e6eec7cf816a704ed3f4f7997fbc25d15df7135fe40cd48dcb51ef",
      "${SDK}/usr/lib/system/libsystem_c.tbd": "ec8bd71d0b1e618222f0cf1b9642e4934c253698fd7179b5e138dfdb105de14a",
      "${SDK}/usr/lib/system/libsystem_kernel.tbd": "563ea4296cf1fdec17b6b561aa77f00cd08a7294b3f9e798999f934629f38004",
      "${SDK}/usr/lib/system/libsystem_malloc.tbd": "606909376f280369e8c744b31ad8beb86d0ec78a2cc268d98d3dc81797834d51",
      "/Applications/Xcode.app/Contents/Info.plist": "537783b4c639af6ee31208fe2ec12a40bacbb0fc8f5dd2820f54e03063c4dbe8",
      "/Applications/Xcode.app/Contents/version.plist": "99aa0f4ffa738d03c9d86b273745d4a3945c7cdc7462221033fb807463d895e9"
    }
  },
  "source_hashes": {
    "native/darwin_bootstrap/CMakeLists.txt": "d4f9c1002b7f1f9f7d86de0287cb108f24797ac194d9c9900df05e25cff5cd6a",
    "native/darwin_bootstrap/a2c_phase3_io.c": "1490cadf5177e4128e71ae6ae629be551651e03670c92aa8968783a42d3d8944",
    "native/darwin_bootstrap/a2c_phase3_io.h": "22889f44cb86df72b411aabf80bd9bf58193ff880e03780a541f36282266aaa1",
    "native/darwin_bootstrap/a2c_phase3_journal.c": "320c3b0987e8bd47da5fdf015f6e65b13158d206c583cc1c95f58a617812e624",
    "native/darwin_bootstrap/a2c_phase3_policy.c": "0caa7485fb3cc1960e7b671e9bffed10cdf02ae689eb6cda4e6adae2af1a2d13",
    "native/darwin_bootstrap/a2c_phase3_policy.h": "9b67bad694f468cae2a4e95b2c61eb3163b845c23a941aec6c9837d48f96435a",
    "native/darwin_bootstrap/a2c_phase3_unavailable.c": "62ea07a5915b94267eb6c02440ff75216b1b9d4a6e3fcfb29ea209f0df0fbe68",
    "native/darwin_bootstrap/a2c_policy.c": "44cd5acd712f59b44d5a04affeaa04b99f4fc0ebc42125ec66864ecbb627b5be",
    "native/darwin_bootstrap/a2c_policy.h": "e1bc86236f4f7621377ea602c360cdd68300c0a80a074ee342409c1213534a9a",
    "native/darwin_bootstrap/abi_v1.h": "7fbbae469c65e53b7a444760bdd09da8ef32c63a5f037956d9cf1123c65e0025",
    "native/darwin_bootstrap/attempt_entry.c": "8a13f4a155b49189a752c9cbb795cb2929f9952f98f7dc6bc90f091b1b424ba8",
    "native/darwin_bootstrap/broker_entry.c": "9416bd683310020d23ff808bba000d22c44d9d86ccdb0f9dd754d67c34d5fba6",
    "native/darwin_bootstrap/broker_entry.h": "fecd4ff9f7a24c8ac39d2f649ba47478ec4b47d74f9319a74430440ca53a98fc",
    "native/darwin_bootstrap/fd_inventory.c": "1a6b7e201f50f96086f3565734e47b03882b911331cd2469e251993ba0320cce",
    "native/darwin_bootstrap/final_entry.c": "b844e9e92b7d8803250c1d1eab175f1495ef2b04014c84479f6788d113c7188d",
    "native/darwin_bootstrap/install_preflight.c": "ac1fde1c34cb491f3a8a5543d28f817a71ab3b66496a55f3a1b0ce461d6285a9",
    "native/darwin_bootstrap/install_preflight.h": "adbeb95f89aa1875f7ffe495bda2f62db719c1449c1014f5f32d5e6838f538dd",
    "native/darwin_bootstrap/install_preflight_main.c": "21d88527a94dadc28b9eb47ee4ee52c2a6cb6e5a2a8f329fb6468cbe05a6920b",
    "native/darwin_bootstrap/install_preflight_unavailable.c": "5e0816b925033c240e5178f9106565b1f3cd944c04c8aad7e4ff5389a1e40e49",
    "native/darwin_bootstrap/launch_authority.c": "5aa66aa52db6d0e5ef8cc5dacbb226350ab1f77f043cd471574b5a3ffcc6da27",
    "native/darwin_bootstrap/launch_authority.h": "6460610f08d101c7e24919a3ce0829d4be36d1c875e6190416814c42a0947767",
    "native/darwin_bootstrap/launch_control.c": "258abb103b9ce45e7910f083b6984d82c9d75917c09d7a37e8cc39e1ea43c6ac",
    "native/darwin_bootstrap/launch_control.h": "03a6cea6d47e0a5712a6a62072eb9a460ef14e055a1bdc0ae08c063e0945b039",
    "native/darwin_bootstrap/path_observer_core_v1.c": "c1b7a3d59ad601f6d2f01f341507f44b1c85d45456d5ec79b4221cce65225275",
    "native/darwin_bootstrap/path_observer_os_darwin_v1.c": "375094851d9a59404fa27b1abcb83e2ebb2ea05401a158b224247d520d7ab771",
    "native/darwin_bootstrap/path_observer_os_v1.h": "f0cfdc8584a834f56fba1e20f018adb633071982deaa37f6c72747b094b05555",
    "native/darwin_bootstrap/path_observer_v1.h": "6a0d6c1ebe81df48fd82bbc19aa02e200a5a753a5301cf0887aa96d8d75b6022",
    "native/darwin_bootstrap/release_manifest.c": "dfa3bba28e68cb47de74d24993b69ec91ec07453012dcb64f81e85077cb6920e",
    "native/darwin_bootstrap/socket_lineage.c": "49d3bd8036c04457bfd2654c79aaa010f7243fcf5e5c15ed6ecee711eecba42d",
    "native/darwin_bootstrap/stage0.c": "7369ad5a6b3ff06ed8ecc0c2be281570cde10cdea6d508e21214a7d2ef04d562",
    "native/darwin_bootstrap/stage0_entry.c": "68e698b38e2cf8ae5027e06e8bda296ec76fb8b6be86ed6efcbc4b8a90b807c3",
    "native/trusted_inbound/darwin/socket_observer.c": "7b6eb5e39dd724cae65067aec0f640b223c55ef50b3a1001c24efbad0486b853",
    "native/trusted_inbound/darwin/socket_observer.h": "167771bcb9b7c1c60f92e48cf963fc5e5baa876b30f7bbcb36a94e1ce0a30d07",
    "tests/native/darwin_bootstrap/path_observer_os_test_v1.c": "580d1541de805779fa1f7500c73e808d650dad17885bb48e6c0bae74d59e4e0f",
    "tests/native/darwin_bootstrap/test_install_preflight.c": "7a486f9c4e75f6c598af03b82fcaa868972f82e3c4d402db0874cdc2ba835f4f",
    "tests/native/darwin_bootstrap/test_install_preflight_adapter.c": "3034d2f39c78b6f60928ffd0aaaaf3df7a553c8cf02448a5c5bbb8df40076bd4",
    "tests/native/darwin_bootstrap/test_path_observer.py": "276177a72836a3bd3c227217087630759975c3afb353432ede0fdf13965d2acf",
    "tests/native/darwin_bootstrap/test_path_observer_injected.c": "6bdbe7e36c19aefe7c0a57e3e86852020dbda046b9b161f7308d777f79204486",
    "tests/native/darwin_bootstrap/test_path_observer_real.c": "7a37244af39b5c12639a6688760fae57fb9acbc5464317ebebc833a54151c16a"
  },
  "targets": {
    "bee_hermes_a2c_phase3_attempt": {
      "defined": [
        "__mh_execute_header",
        "_bh_a2a_child_actions",
        "_bh_a2a_child_map_prepare",
        "_bh_a2a_child_map_retire",
        "_bh_a2a_frame_sign",
        "_bh_a2a_frame_verify",
        "_bh_a2a_inventory_check",
        "_bh_a2a_manifest_validate",
        "_bh_a2a_root_bind_observe",
        "_bh_a2a_root_cancel",
        "_bh_a2a_root_cleanup_leaf",
        "_bh_a2a_root_prepare_fd6",
        "_bh_a2a_root_retire_and_signal",
        "_bh_a2c_candidate",
        "_bh_a2c_channel_init",
        "_bh_a2c_check_alive",
        "_bh_a2c_frame_decode",
        "_bh_a2c_frame_encode",
        "_bh_a2c_guard",
        "_bh_a2c_now",
        "_bh_a2c_pending",
        "_bh_a2c_phase2",
        "_bh_a2c_phase3_check_pending",
        "_bh_a2c_phase3_core",
        "_bh_a2c_phase3_core_valid",
        "_bh_a2c_phase3_frame",
        "_bh_a2c_phase3_images",
        "_bh_a2c_phase3_journal_encode",
        "_bh_a2c_phase3_manifest",
        "_bh_a2c_phase3_manifest_valid",
        "_bh_a2c_phase3_pending",
        "_bh_a2c_phase3_read_eof",
        "_bh_a2c_phase3_shutdown",
        "_bh_a2c_phase3_verify",
        "_bh_a2c_phase3_write",
        "_bh_a2c_receive",
        "_bh_a2c_retire",
        "_bh_a2c_send",
        "_bh_a2c_signals_match",
        "_bh_a2c_spawn",
        "_bh_darwin_observe_fd6",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "d446548668db9ecd5a5e47d0b321bf22469759fd5b1982fe487ff9e0ff325e59",
      "imports": [
        "_CCHmac",
        "_CC_SHA256",
        "_CC_SHA256_Final",
        "_CC_SHA256_Init",
        "_CC_SHA256_Update",
        "___chkstk_darwin",
        "___error",
        "___memcpy_chk",
        "___memset_chk",
        "___snprintf_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "__exit",
        "_bind",
        "_bzero",
        "_clock_gettime",
        "_close",
        "_dup2",
        "_fcntl",
        "_flock",
        "_fstat",
        "_fstatat",
        "_fsync",
        "_ftruncate",
        "_getgid",
        "_getpeername",
        "_getpid",
        "_getsockname",
        "_getsockopt",
        "_getuid",
        "_kill",
        "_memchr",
        "_memcmp",
        "_memcpy",
        "_memset",
        "_nanosleep",
        "_open",
        "_openat",
        "_pipe",
        "_poll",
        "_posix_spawn",
        "_posix_spawn_file_actions_addclose",
        "_posix_spawn_file_actions_adddup2",
        "_posix_spawn_file_actions_destroy",
        "_posix_spawn_file_actions_init",
        "_posix_spawnattr_destroy",
        "_posix_spawnattr_init",
        "_posix_spawnattr_setflags",
        "_posix_spawnattr_setsigdefault",
        "_posix_spawnattr_setsigmask",
        "_pread",
        "_proc_pidfdinfo",
        "_proc_pidinfo",
        "_pwrite",
        "_qsort",
        "_read",
        "_recv",
        "_send",
        "_shutdown",
        "_sigaction",
        "_sigprocmask",
        "_socket",
        "_socketpair",
        "_strchr",
        "_strcmp",
        "_strlen",
        "_strnlen",
        "_sysctlbyname",
        "_uname",
        "_unlinkat",
        "_waitpid"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_a2c_phase3_attempt.map",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/attempt_entry.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/launch_control.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_journal.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_io.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_unavailable.c.o",
        "-o",
        "bee_hermes_a2c_phase3_attempt",
        "libbee_hermes_a2a.a"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/attempt_entry.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/launch_control.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_journal.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_io.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_attempt.dir/a2c_phase3_unavailable.c.o",
        "libbee_hermes_a2a.a(launch_authority.c.o)",
        "libbee_hermes_a2a.a(release_manifest.c.o)",
        "libbee_hermes_a2a.a(fd_inventory.c.o)",
        "libbee_hermes_a2a.a(socket_lineage.c.o)",
        "libbee_hermes_a2a.a(socket_observer.c.o)",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libcommonCrypto.tbd",
        "${SDK}/usr/lib/system/libcompiler_rt.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd",
        "${SDK}/usr/lib/system/libsystem_kernel.tbd"
      ],
      "normalized_map_sha256": "739e3b7b800b9481e0e05f01017e5a6ac8a5b32e2566bee26d4d9edd9d7bd106",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 4,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            472
          ],
          [
            25,
            232
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "bee_hermes_a2c_phase3_final": {
      "defined": [
        "__mh_execute_header",
        "_bh_a2a_child_actions",
        "_bh_a2a_child_map_prepare",
        "_bh_a2a_child_map_retire",
        "_bh_a2a_frame_sign",
        "_bh_a2a_frame_verify",
        "_bh_a2a_inventory_check",
        "_bh_a2a_root_cancel",
        "_bh_a2a_root_prepare_fd6",
        "_bh_a2a_root_retire_and_signal",
        "_bh_a2c_channel_init",
        "_bh_a2c_check_alive",
        "_bh_a2c_frame_decode",
        "_bh_a2c_frame_encode",
        "_bh_a2c_guard",
        "_bh_a2c_now",
        "_bh_a2c_phase3_core",
        "_bh_a2c_phase3_core_valid",
        "_bh_a2c_phase3_frame",
        "_bh_a2c_phase3_manifest",
        "_bh_a2c_phase3_read_eof",
        "_bh_a2c_phase3_shutdown",
        "_bh_a2c_phase3_verify",
        "_bh_a2c_phase3_write",
        "_bh_a2c_receive",
        "_bh_a2c_retire",
        "_bh_a2c_send",
        "_bh_a2c_signals_match",
        "_bh_a2c_spawn",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "fe769c75d6052d33679eb5f52788b635898768f06e9ec2a40a19c7ddaed36687",
      "imports": [
        "_CCHmac",
        "_CC_SHA256",
        "_CC_SHA256_Final",
        "_CC_SHA256_Init",
        "_CC_SHA256_Update",
        "___chkstk_darwin",
        "___error",
        "___memcpy_chk",
        "___memset_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "__exit",
        "_clock_gettime",
        "_close",
        "_dup2",
        "_fcntl",
        "_fstat",
        "_getpeername",
        "_getpid",
        "_getsockname",
        "_getsockopt",
        "_kill",
        "_memcmp",
        "_memset",
        "_poll",
        "_posix_spawn",
        "_posix_spawn_file_actions_addclose",
        "_posix_spawn_file_actions_adddup2",
        "_posix_spawn_file_actions_destroy",
        "_posix_spawn_file_actions_init",
        "_posix_spawnattr_destroy",
        "_posix_spawnattr_init",
        "_posix_spawnattr_setflags",
        "_posix_spawnattr_setsigdefault",
        "_posix_spawnattr_setsigmask",
        "_proc_pidinfo",
        "_qsort",
        "_recv",
        "_send",
        "_shutdown",
        "_sigaction",
        "_sigprocmask",
        "_socket",
        "_strnlen"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_a2c_phase3_final.map",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/final_entry.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_io.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_unavailable.c.o",
        "-o",
        "bee_hermes_a2c_phase3_final",
        "libbee_hermes_a2c_phase1.a",
        "libbee_hermes_a2a.a"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/final_entry.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_policy.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_io.c.o",
        "CMakeFiles/bee_hermes_a2c_phase3_final.dir/a2c_phase3_unavailable.c.o",
        "libbee_hermes_a2c_phase1.a(launch_control.c.o)",
        "libbee_hermes_a2a.a(launch_authority.c.o)",
        "libbee_hermes_a2a.a(fd_inventory.c.o)",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libcommonCrypto.tbd",
        "${SDK}/usr/lib/system/libcompiler_rt.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd",
        "${SDK}/usr/lib/system/libsystem_kernel.tbd"
      ],
      "normalized_map_sha256": "4fb2d2587bd5b5e48cf242fe3d79ad1f3fc25ee0c78dac7b1441bdd0d24bc9aa",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 4,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            392
          ],
          [
            25,
            152
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "bee_hermes_a2c_phase3_stage0": {
      "defined": [
        "__mh_execute_header",
        "_bh_a2a_child_actions",
        "_bh_a2a_child_map_prepare",
        "_bh_a2a_child_map_retire",
        "_bh_a2a_inventory_check",
        "_bh_a2a_stage0_drop",
        "_bh_a2a_stage0_validate",
        "_bh_a2c_channel_init",
        "_bh_a2c_check_alive",
        "_bh_a2c_guard",
        "_bh_a2c_now",
        "_bh_a2c_receive",
        "_bh_a2c_send",
        "_bh_a2c_signals_match",
        "_bh_a2c_spawn",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "499b56af4d8d111c1c992d278d49c0442b3b06991368083be108df8d5a7ad848",
      "imports": [
        "_CC_SHA256_Final",
        "_CC_SHA256_Init",
        "_CC_SHA256_Update",
        "___chkstk_darwin",
        "___error",
        "___memset_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "__exit",
        "_clock_gettime",
        "_close",
        "_execve",
        "_fcntl",
        "_fstat",
        "_getegid",
        "_geteuid",
        "_getgid",
        "_getpid",
        "_getsockname",
        "_getsockopt",
        "_getuid",
        "_poll",
        "_posix_spawn",
        "_posix_spawn_file_actions_addclose",
        "_posix_spawn_file_actions_adddup2",
        "_posix_spawn_file_actions_destroy",
        "_posix_spawn_file_actions_init",
        "_posix_spawnattr_destroy",
        "_posix_spawnattr_init",
        "_posix_spawnattr_setflags",
        "_posix_spawnattr_setsigdefault",
        "_posix_spawnattr_setsigmask",
        "_proc_pidinfo",
        "_qsort",
        "_recv",
        "_send",
        "_seteuid",
        "_setgid",
        "_setgroups",
        "_setuid",
        "_sigaction",
        "_sigprocmask",
        "_write"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_a2c_phase3_stage0.map",
        "CMakeFiles/bee_hermes_a2c_phase3_stage0.dir/stage0_entry.c.o",
        "-o",
        "bee_hermes_a2c_phase3_stage0",
        "libbee_hermes_a2c_phase1.a",
        "libbee_hermes_a2a.a"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_a2c_phase3_stage0.dir/stage0_entry.c.o",
        "libbee_hermes_a2c_phase1.a(launch_control.c.o)",
        "libbee_hermes_a2a.a(stage0.c.o)",
        "libbee_hermes_a2a.a(fd_inventory.c.o)",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libcommonCrypto.tbd",
        "${SDK}/usr/lib/system/libcompiler_rt.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd",
        "${SDK}/usr/lib/system/libsystem_kernel.tbd"
      ],
      "normalized_map_sha256": "273dd498e3e914808e7f8d1e3b18255d0ee800e332e9d8fb6902383eb71412e0",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 4,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            472
          ],
          [
            25,
            232
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "bee_hermes_install_preflight_test": {
      "defined": [
        "__mh_execute_header",
        "_bh_install_preflight",
        "_bh_install_preflight_reason",
        "_bh_install_preflight_unavailable_provider",
        "_bh_ip_test_synthetic_provider",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "08e3a4aa174ad5799d88070d5d17bcb6fe18490bb988a33b4192263f96e1567e",
      "imports": [
        "___memcpy_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "___strcpy_chk",
        "_bzero",
        "_memcmp",
        "_memcpy",
        "_memset",
        "_printf",
        "_strcmp"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_install_preflight_test.map",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight_unavailable.c.o",
        "-o",
        "bee_hermes_install_preflight_test"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_install_preflight_adapter.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight.c.o",
        "CMakeFiles/bee_hermes_install_preflight_test.dir/install_preflight_unavailable.c.o",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd"
      ],
      "normalized_map_sha256": "b01a41312eda8aed59580d0045bd03ebb6224448eb2ecf3cfead64bcfbc8b0bd",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 5,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            472
          ],
          [
            25,
            152
          ],
          [
            25,
            152
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "bee_hermes_path_observer_v1_injected_test": {
      "defined": [
        "__mh_execute_header",
        "_bh_po_observe_v1",
        "_bh_po_os_acl_first",
        "_bh_po_os_acl_free",
        "_bh_po_os_acl_get",
        "_bh_po_os_acl_valid",
        "_bh_po_os_close",
        "_bh_po_os_dup_cloexec",
        "_bh_po_os_fstat",
        "_bh_po_os_fstatat",
        "_bh_po_os_openat",
        "_bh_po_test_acl",
        "_bh_po_test_acl_alloc_count",
        "_bh_po_test_acl_free_count",
        "_bh_po_test_acl_get_count",
        "_bh_po_test_acl_live",
        "_bh_po_test_after_open_hook_acl_count",
        "_bh_po_test_after_open_hook_count",
        "_bh_po_test_after_open_hook_fstat_count",
        "_bh_po_test_after_open_hook_fstatat_count",
        "_bh_po_test_case_max_owned",
        "_bh_po_test_change_after_open_fstat",
        "_bh_po_test_close_count",
        "_bh_po_test_fail",
        "_bh_po_test_first_null_success",
        "_bh_po_test_live_owned",
        "_bh_po_test_max_owned",
        "_bh_po_test_mutate_before_open",
        "_bh_po_test_mutation_done",
        "_bh_po_test_next_acl_eio_after_replacement",
        "_bh_po_test_next_call_count",
        "_bh_po_test_op_count",
        "_bh_po_test_open_count",
        "_bh_po_test_open_success_count",
        "_bh_po_test_os_call_count",
        "_bh_po_test_reset",
        "_bh_po_test_resets_with_live_resources",
        "_bh_po_test_root_change_after_acl",
        "_bh_po_test_set_replacement",
        "_bh_po_test_zero_link",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "3122af6f9031175a547bd3f690a34878f7bdc28c9193df42229e97759676b2e6",
      "imports": [
        "___chkstk_darwin",
        "___error",
        "___memcpy_chk",
        "___memset_chk",
        "___snprintf_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "___stderrp",
        "___strcpy_chk",
        "_acl_add_perm",
        "_acl_create_entry",
        "_acl_free",
        "_acl_get_entry",
        "_acl_get_fd_np",
        "_acl_get_permset",
        "_acl_init",
        "_acl_set_qualifier",
        "_acl_set_tag_type",
        "_acl_valid",
        "_bind",
        "_bzero",
        "_close",
        "_dup",
        "_fchmod",
        "_fcntl",
        "_fprintf",
        "_free",
        "_fstat",
        "_fstatat",
        "_linkat",
        "_malloc",
        "_memcmp",
        "_memcpy",
        "_memset",
        "_mkdirat",
        "_mkdtemp",
        "_mkfifoat",
        "_open",
        "_openat",
        "_pread",
        "_printf",
        "_readlinkat",
        "_renameat",
        "_rmdir",
        "_socket",
        "_strcmp",
        "_strlen",
        "_symlinkat",
        "_unlinkat",
        "_write"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_path_observer_v1_injected_test.map",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c.o",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c.o",
        "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o",
        "-o",
        "bee_hermes_path_observer_v1_injected_test"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_injected.c.o",
        "CMakeFiles/bee_hermes_path_observer_v1_injected_test.dir${SOURCE}/tests/native/darwin_bootstrap/path_observer_os_test_v1.c.o",
        "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libcompiler_rt.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd",
        "${SDK}/usr/lib/system/libsystem_kernel.tbd",
        "${SDK}/usr/lib/system/libsystem_malloc.tbd"
      ],
      "normalized_map_sha256": "dad8832892f1cb1547fbc2ed022d6c38a2a000a00c93fc9d908cc26a15f9843b",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 5,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            472
          ],
          [
            25,
            152
          ],
          [
            25,
            232
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "bee_hermes_path_observer_v1_real_test": {
      "defined": [
        "__mh_execute_header",
        "_bh_po_observe_v1",
        "_bh_po_os_acl_first",
        "_bh_po_os_acl_free",
        "_bh_po_os_acl_get",
        "_bh_po_os_acl_valid",
        "_bh_po_os_close",
        "_bh_po_os_dup_cloexec",
        "_bh_po_os_fstat",
        "_bh_po_os_fstatat",
        "_bh_po_os_openat",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "14677eab6f798608451cba4ecc6866cb249458dc96c63996cf6c3aef588639e7",
      "imports": [
        "___chkstk_darwin",
        "___error",
        "___memcpy_chk",
        "___memset_chk",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "___stderrp",
        "___strcpy_chk",
        "_acl_free",
        "_acl_get_entry",
        "_acl_get_fd_np",
        "_acl_valid",
        "_bzero",
        "_close",
        "_dup",
        "_fcntl",
        "_fprintf",
        "_free",
        "_fstat",
        "_fstatat",
        "_malloc",
        "_memcpy",
        "_mkdtemp",
        "_open",
        "_openat",
        "_printf",
        "_rmdir",
        "_strcmp",
        "_unlinkat"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/bee_hermes_path_observer_v1_real_test.map",
        "CMakeFiles/bee_hermes_path_observer_v1_real_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c.o",
        "-o",
        "bee_hermes_path_observer_v1_real_test",
        "libbee_hermes_path_observer_v1.a"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/bee_hermes_path_observer_v1_real_test.dir${SOURCE}/tests/native/darwin_bootstrap/test_path_observer_real.c.o",
        "libbee_hermes_path_observer_v1.a(path_observer_os_darwin_v1.c.o)",
        "libbee_hermes_path_observer_v1.a(path_observer_core_v1.c.o)",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libcompiler_rt.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd",
        "${SDK}/usr/lib/system/libsystem_kernel.tbd",
        "${SDK}/usr/lib/system/libsystem_malloc.tbd"
      ],
      "normalized_map_sha256": "489b1e0b1e8607038ec600230df2a420df075d6d4083478ae05f57a5ea9a98a4",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 5,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            392
          ],
          [
            25,
            152
          ],
          [
            25,
            152
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    },
    "hermes_bee_install_preflight": {
      "defined": [
        "__mh_execute_header",
        "_bh_install_preflight",
        "_bh_install_preflight_reason",
        "_bh_install_preflight_unavailable_provider",
        "_main"
      ],
      "dependencies": [
        "/usr/lib/libSystem.B.dylib"
      ],
      "image_sha256": "9381a6bf0098add73dc7e2acea56df84346660e76e01c0ff0d9610f6ca62b24f",
      "imports": [
        "___stack_chk_fail",
        "___stack_chk_guard",
        "_memcmp",
        "_memset",
        "_printf",
        "_puts",
        "_strcmp"
      ],
      "link_argv": [
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        "-arch",
        "arm64",
        "-isysroot",
        "${SDK}",
        "-mmacosx-version-min=27.0",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        "-Xlinker",
        "-map",
        "-Xlinker",
        "${BUILD}/hermes_bee_install_preflight.map",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_main.c.o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight.c.o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_unavailable.c.o",
        "-o",
        "hermes_bee_install_preflight"
      ],
      "map_rows": [
        "linker synthesized",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_main.c.o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight.c.o",
        "CMakeFiles/hermes_bee_install_preflight.dir/install_preflight_unavailable.c.o",
        "${SDK}/usr/lib/libSystem.tbd",
        "${SDK}/usr/lib/system/libsystem_c.tbd"
      ],
      "normalized_map_sha256": "b3d2d051c35e58f398bbd9dd4c76e8cf2c187ed7f07e5a333e75a9ca9b796f1d",
      "raw": {
        "build_version": [
          1,
          1769472,
          1769472,
          [
            [
              3,
              1771897088
            ]
          ]
        ],
        "command_counts": {
          "11": 1,
          "12": 1,
          "14": 1,
          "2": 1,
          "2147483688": 1,
          "2147483699": 1,
          "2147483700": 1,
          "25": 4,
          "27": 1,
          "29": 1,
          "38": 1,
          "41": 1,
          "42": 1,
          "50": 1
        },
        "command_shapes": [
          [
            25,
            72
          ],
          [
            25,
            472
          ],
          [
            25,
            152
          ],
          [
            25,
            72
          ],
          [
            2147483700,
            16
          ],
          [
            2147483699,
            16
          ],
          [
            2,
            24
          ],
          [
            11,
            80
          ],
          [
            14,
            32
          ],
          [
            27,
            24
          ],
          [
            50,
            32
          ],
          [
            42,
            16
          ],
          [
            2147483688,
            24
          ],
          [
            12,
            56
          ],
          [
            38,
            16
          ],
          [
            41,
            16
          ],
          [
            29,
            16
          ]
        ],
        "dyld": "/usr/lib/dyld",
        "dylibs": [
          "/usr/lib/libSystem.B.dylib"
        ],
        "flags": 2097285
      }
    }
  },
  "toolchain_bytes": {
    "ar": {
      "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar",
      "sha256": "85d15bd3999895f659e8a483b17ea9ab44b924c8e0b3026abfe359f2de02cbd7"
    },
    "clang": {
      "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
      "sha256": "1590ac950a3d627817d09ade5cb60b2115f17a72182a3141e010b4bcc482a0c9"
    },
    "ld": {
      "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld",
      "sha256": "374d9f0713bce2c8a9e1e82bde51615d5433516a10d99b63107eb6ee70542e4c"
    },
    "nm": {
      "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-nm",
      "sha256": "82e9189ec1a359699d4b680601c0a2930a9cbea7376c7320947dff5e9862cfa8"
    },
    "otool": {
      "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-otool",
      "sha256": "8353ad3c42743a93e9ca7d0d4e9d3df22305252d169c42c543ee22eeb8c33809"
    },
    "xcrun": {
      "path": "/usr/bin/xcrun",
      "sha256": "bbe7671518a3905f9d3fce54312fbc77c2876b0d62aca74a0688fa869d31a8a9"
    }
  }
}
```
