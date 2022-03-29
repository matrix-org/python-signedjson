1. Set a variable to the version number for convenience:
   ```sh
   ver=x.y.z
   ```
1. Update the changelog:
   ```sh
   towncrier --version=$ver
   # On newer towncriers: towncrier build --version=$ver
   ```
1. Push your changes:
   ```sh
   git add -u && git commit -m $ver && git push
   ```
1. Sanity-check the
   [changelog](https://github.com/matrix-org/python-signedjson/blob/master/CHANGELOG.md)
   and update if need be.
1. Create a signed tag for the relese:
   ```sh
   git tag -s v$ver
   ```
   Base the tag message on the changelog.
1. Push the tag:
   ```sh
   git push origin tag v$ver
   ```
1. Build and upload to PyPI:
   ```sh
   python setup.py sdist
   twine upload dist/python-signedjson-$ver.tar.gz
   ```
1. Create release on GH project page:
   ```sh
   xdg-open https://github.com/matrix-org/python-signedjson/releases/edit/v$ver
   ```
