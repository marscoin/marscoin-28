.PHONY: FORCE
all: FORCE
	$(MAKE) -C .. marscoin_qt test_marscoin_qt
clean: FORCE
	$(MAKE) -C .. marscoin_qt_clean test_marscoin_qt_clean
check: FORCE
	$(MAKE) -C .. test_marscoin_qt_check
marscoin-qt marscoin-qt.exe: FORCE
	 $(MAKE) -C .. marscoin_qt
apk: FORCE
	$(MAKE) -C .. marscoin_qt_apk
