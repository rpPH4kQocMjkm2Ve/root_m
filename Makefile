.PHONY: perms

perms:
	chezmoi managed --path-style=absolute | \
		python3 /root/.local/share/chezmoi/scripts/apply_perms.py \
			--perms-file /root/.local/share/chezmoi/chezmoiperms \
			--dest-dir / \
			--managed-paths -
