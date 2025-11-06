.PHONY: release help

help:
	@echo "Available targets:"
	@echo "  release VERSION=x.y.z      - Release ssl-storage: bump version, commit, tag v*, and push"
	@echo "  help                             - Show this help message"

release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "Releasing ssl-storage version $(VERSION)..."
	@sed -i.bak 's/^VERSION=.*$$/VERSION=$(VERSION)/' install.sh && rm install.sh.bak
	@sed -i.bak 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml && rm Cargo.toml.bak
	@cargo update -p ssl-storage
	@git add Cargo.toml Cargo.lock install.sh
	@git commit -m "chore: release ssl-storage $(VERSION)"
	@git tag v$(VERSION)
	@git push origin main
	@git push origin tag v$(VERSION)
	@echo "Ssl-storage version $(VERSION) released successfully!"
