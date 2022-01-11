package report

// PackageManager is a unique string identifier of the package manager.
type PackageManager string

const (
	// PackageManagerBundler is the identifier for Ruby Bundler
	PackageManagerBundler = "bundler"
	// PackageManagerComposer is the identifier for PHP Composer
	PackageManagerComposer = "composer"
	// PackageManagerMaven is the identifier for Java Maven
	PackageManagerMaven = "maven"
	// PackageManagerNpm is the identifier for npm
	PackageManagerNpm = "npm"
	// PackageManagerPip is the identifier for Python's pip
	PackageManagerPip = "pip"
	// PackageManagerYarn is the identifier for yarn
	PackageManagerYarn = "yarn"
)

// DependencyFile holds the dependencies manifest file build by a particular package manager.
type DependencyFile struct {
	Path           string         `json:"path"`            // Path relative to the repository root.
	PackageManager PackageManager `json:"package_manager"` // Package manager used to process this file.
	Dependencies   []Dependency   `json:"dependencies"`    // Dependencies explicitly listed or implicitly required by the file.
}
