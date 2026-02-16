MAINFILE = main
OUTPUTDIR = _build

.PHONY: all
all:
	latexmk -pdf -shell-escape -interaction=batchmode -outdir=$(OUTPUTDIR) $(MAINFILE).tex

.PHONY: watch
watch:
	latexmk -pdf -shell-escape -pvc -outdir=$(OUTPUTDIR) $(MAINFILE).tex

.PHONY: clean
clean:
	latexmk -c -outdir=$(OUTPUTDIR)
	latexmk -c

.PHONY: distclean
distclean:
	latexmk -C -outdir=$(OUTPUTDIR)
	latexmk -C
	rm -rf $(OUTPUTDIR)
