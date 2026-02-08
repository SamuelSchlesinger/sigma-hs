import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (localPkgDescr, withLibLBI, componentBuildDir)
import System.Process (callProcess)
import System.Directory (getCurrentDirectory, copyFile, createDirectoryIfMissing)
import System.FilePath ((</>))

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = \(gpd, hbi) flags -> do
      cwd <- getCurrentDirectory
      let manifestPath = cwd </> "rust" </> "sigma-ffi" </> "Cargo.toml"
      -- Build the Rust FFI library before configure checks for it
      callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]
      lbi <- confHook simpleUserHooks (gpd, hbi) flags
      let rustLibDir = cwd </> "rust" </> "sigma-ffi" </> "target" </> "release"
      -- Copy the native library into the component build directory so
      -- extra-bundled-libraries can find it.
      withLibLBI (localPkgDescr lbi) lbi $ \_ clbi -> do
        let bdir = cwd </> componentBuildDir lbi clbi
        createDirectoryIfMissing True bdir
        copyFile (rustLibDir </> "libsigma_ffi.a") (bdir </> "libsigma_ffi.a")
      return lbi
  }
