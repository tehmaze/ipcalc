all: docs clean

docs:
	make -C doc/ html

clean:
	find . -name \*.pyc -exec rm {} \;

push: docs
	hg push /home/hg/projects/ipcalc
	hg push ssh://wijnand@10.23.5.1/code0/trac/data/ipcalc/
	rsync -avP doc/build/html/ wijnand@10.23.5.1:code0/trac/docs/ipcalc/

