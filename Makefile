.DEFAULT_GOAL := help
MODE ?= lite

help:
	@echo "Targets:"
	@echo "  make demo MODE=lite|full   # (will work after Step 2/9)"
	@echo "  make clean                 # stop containers & prune volumes"
	@echo "  make verify                # dataset checksum verify (later)"

demo:
	cd compose && docker compose --profile ui -f docker-compose.$(MODE).yml up --build

clean:
	cd compose && docker compose -f docker-compose.$(MODE).yml down -v

verify:
	./scripts/verify_checksums.sh
