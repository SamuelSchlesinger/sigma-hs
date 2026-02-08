import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (LocalBuildInfo, localPkgDescr, withLibLBI, componentBuildDir)
import Distribution.Types.BuildInfo (BuildInfo, extraLibDirs)
import Distribution.Types.Library (Library, libBuildInfo)
import Distribution.Types.PackageDescription (PackageDescription, library)
import System.Process (callProcess)
import System.Directory (getCurrentDirectory, makeAbsolute)
import System.FilePath ((</>))

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = \(gpd, hbi) flags -> do
      lbi <- confHook simpleUserHooks (gpd, hbi) flags
      cwd <- getCurrentDirectory
      let absLibDir = cwd </> "rust" </> "sigma-ffi" </> "target" </> "release"
      -- Update extra-lib-dirs to use absolute path
      let pd = localPkgDescr lbi
      case library pd of
        Nothing -> return lbi
        Just lib -> do
          let bi = libBuildInfo lib
              bi' = bi { extraLibDirs = absLibDir : filter (/= "rust/sigma-ffi/target/release") (extraLibDirs bi) }
              lib' = lib { libBuildInfo = bi' }
              pd' = pd { library = Just lib' }
          return lbi { localPkgDescr = pd' }
  , preBuild = \args buildFlags -> do
      cwd <- getCurrentDirectory
      let manifestPath = cwd </> "rust" </> "sigma-ffi" </> "Cargo.toml"
      callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]
      preBuild simpleUserHooks args buildFlags
  }
