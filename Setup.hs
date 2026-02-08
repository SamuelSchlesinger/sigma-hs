import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (LocalBuildInfo, localPkgDescr, withLibLBI, componentBuildDir)
import Distribution.Types.BuildInfo (BuildInfo, extraLibDirs)
import Distribution.Types.Library (Library, libBuildInfo)
import Distribution.Types.PackageDescription (PackageDescription, library)
import System.Process (callProcess)
import System.Directory (getCurrentDirectory, copyFile, createDirectoryIfMissing)
import System.FilePath ((</>))
import Data.IORef

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = \(gpd, hbi) flags -> do
      cwd <- getCurrentDirectory
      let manifestPath = cwd </> "rust" </> "sigma-ffi" </> "Cargo.toml"
      -- Build the Rust FFI library before configure checks for it
      callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]
      lbi <- confHook simpleUserHooks (gpd, hbi) flags
      let rustLibDir = cwd </> "rust" </> "sigma-ffi" </> "target" </> "release"
      -- Copy the native library into the component build directory so it
      -- gets installed alongside the Haskell library and is available to
      -- downstream packages.
      buildDirRef <- newIORef Nothing
      withLibLBI (localPkgDescr lbi) lbi $ \_ clbi -> do
        let bdir = componentBuildDir lbi clbi
        createDirectoryIfMissing True bdir
        copyFile (rustLibDir </> "libsigma_ffi.a") (bdir </> "libsigma_ffi.a")
        writeIORef buildDirRef (Just bdir)
      mBuildDir <- readIORef buildDirRef
      -- Update extra-lib-dirs to use the component build directory
      let pd = localPkgDescr lbi
      case (mBuildDir, library pd) of
        (Just bdir, Just lib) -> do
          let bi = libBuildInfo lib
              bi' = bi { extraLibDirs = bdir : filter (/= "rust/sigma-ffi/target/release") (extraLibDirs bi) }
              lib' = lib { libBuildInfo = bi' }
              pd' = pd { library = Just lib' }
          return lbi { localPkgDescr = pd' }
        _ -> return lbi
  }
