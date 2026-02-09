import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (localPkgDescr, withLibLBI, componentBuildDir)
import Distribution.Simple.Setup (configExtraLibDirs)
import System.Process (callProcess)
import System.Directory (getCurrentDirectory, copyFile, createDirectoryIfMissing)
import System.FilePath ((</>))

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = \(gpd, hbi) flags -> do
      cwd <- getCurrentDirectory
      let manifestPath = cwd </> "rust" </> "sigma-ffi" </> "Cargo.toml"
          rustLibDir   = cwd </> "rust" </> "sigma-ffi" </> "target" </> "release"
      -- Build the Rust FFI static library before configure checks for it
      callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]
      -- Add the Rust output directory to the library search path so
      -- configure can find libsigma_ffi when checking extra-libraries.
      let flags' = flags
            { configExtraLibDirs = configExtraLibDirs flags
                                ++ [rustLibDir]
            }
      lbi <- confHook simpleUserHooks (gpd, hbi) flags'
      -- Copy the static library into the component build directory so
      -- GHC can find it when linking the Haskell shared library.
      withLibLBI (localPkgDescr lbi) lbi $ \_ clbi -> do
        let bdir = cwd </> componentBuildDir lbi clbi
        createDirectoryIfMissing True bdir
        copyFile (rustLibDir </> "libsigma_ffi.a")
                 (bdir </> "libsigma_ffi.a")
      return lbi
  }
