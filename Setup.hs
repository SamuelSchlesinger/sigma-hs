import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (LocalBuildInfo, localPkgDescr, withLibLBI, componentBuildDir)
import Distribution.System (OS(..), buildOS)
import System.Process (callProcess)
import System.Directory (getCurrentDirectory, copyFile, createDirectoryIfMissing)
import System.FilePath ((</>))

-- | The shared library extension for the current OS.
dynlibExt :: String
dynlibExt = case buildOS of
  OSX   -> "dylib"
  _     -> "so"

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = \(gpd, hbi) flags -> do
      cwd <- getCurrentDirectory
      let manifestPath = cwd </> "rust" </> "sigma-ffi" </> "Cargo.toml"
      -- Build the Rust FFI library before configure checks for it
      callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]
      lbi <- confHook simpleUserHooks (gpd, hbi) flags
      let rustLibDir = cwd </> "rust" </> "sigma-ffi" </> "target" </> "release"
      -- Copy both static and shared native libraries into the component
      -- build directory so extra-bundled-libraries can find them.
      --
      -- Cabal's naming convention for extra-bundled-libraries with a "C"
      -- prefix (e.g. Csigma_ffi):
      --   Static:  libCsigma_ffi.a      (raw name, no stripping)
      --   Shared:  libsigma_ffi.dylib   (C prefix stripped)
      withLibLBI (localPkgDescr lbi) lbi $ \_ clbi -> do
        let bdir = cwd </> componentBuildDir lbi clbi
        createDirectoryIfMissing True bdir
        copyFile (rustLibDir </> "libsigma_ffi.a")
                 (bdir </> "libCsigma_ffi.a")
        copyFile (rustLibDir </> ("libsigma_ffi." ++ dynlibExt))
                 (bdir </> ("libsigma_ffi." ++ dynlibExt))
      return lbi
  }
