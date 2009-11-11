dist_man_MANS = dv2sqlite.1

EXTRA_DIST = dv2sqlite.xml

all: $(dist_man_MANS)

%.1: %.xml
	xmlto man $<
