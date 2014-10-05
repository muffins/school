This folder implements delegation of unclaimed targets to bins. 
Currently the code uses 1024 bins and generated the associated metadata into the original repository.

Files of interest:
https://github.com/theupdateframework/pypi.updateframework.com
delegate.py
delegate_unclaimed_targets.py

Several modifications have been performed to the files above to support the current repository. 

Test procedure:
$ make all

To update:
$ make update

Results:
- 1024 bins created, first run took ~3 minutes.
- Consecutive runs took ~1.5 minutes.
- Tested with gemsontuf successfully

