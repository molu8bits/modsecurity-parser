MODULE := modsecurity_parser
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BYELLOW='\033[1;33m'
UYELLOW='\033[4;33m'
OYELLOW='\033[43m'
NC='\033[0m' # No color

run:
	@python -m $(MODULE)

integration-v2:
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2.log -j out-v2.json -x out-v2.xlsx -g out-v2.png

integration-v3:
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v3.log -j out-v3.json -x out-v3.xlsx -g out-v3.png --version3

integration-v2-json:
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2_json.log -j out-v2-json.json -x out-v2-json.xlsx -g out-v2-json.png --jsonaudit

integration-v2-timems:
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2_timems.log -j out-v2-timems.json -x out-v2-timems.xlsx -g out-v2-timems.png

test-e2e:
	@echo "\n${BLUE}Running E2E tests on sample_audit_log folder ${NC}\n"
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2.log -j out-v2.json -x out-v2.xlsx -g out-v2.png
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v3.log -j out-v3.json -x out-v3.xlsx -g out-v3.png --version3
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2_json.log -j out-v2-json.json -x out-v2-json.xlsx -g out-v2-json.png --jsonaudit
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2_utc_minus.log -j out-v2-utc-minus -x out-v2-utc-minus.xlsx -g out-v2-utc-minus.png
	@python -m ${MODULE} -f sample_audit_log/modsec_audit_v2_timems.log -j out-v2-timems.json -x out-v2-timems.xlsx -g out-v2-timems.png

test:
	@echo "\n${OYELLOW}Running Pylint against source and test files...${NC}\n"
	@pytest

lint:
    # test comments
	@echo "\n${BLUE}Running Pylint against source and test files...${NC}\n"
	# @pylint --rcfile=setup.cfg **/*.py *.py
	# @pylint --rcfile=setup.cfg *.py
	@pylint --rcfile=setup.cfg *.py --output-format=parseable --output pylint-output.txt --exit-zero
	@echo "\n${BLUE}Running PyDocStyle against source files...${NC}\n"
	@pydocstyle --config=setup.cfg modsecurity_parser.py
	@echo "\n${BLUE}Running Flake8 against source and test files...${NC}\n"
	@flake8
	@echo "\n${BLUE}Running Bandit against source files...${NC}\n"
	# @bandit -r --ini setup.cfg
	@bandit -r --ini setup.cfg
	@echo "\n${BLUE}Running pycodestyle against source files...${NC}\n"
	@pycodestyle modsecurity_parser.py
	@echo "\n${BLUE}Running Code Coverage against source files...${NC}\n"
	# @pytest --cov=modsecurity_parser tests --cov-report=html
	# @pytest

clean:
	rm -rf .pytest_cache .coverage .pytest_cache coverage.xml sample_audit_log/modsec_output

.PHONY: clean test
