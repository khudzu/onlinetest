import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from main.crypto.aes_hqc import generate_hqc_keypair


class Command(BaseCommand):
    help = "Generate one persistent HQC keypair and write it to a protected env file."
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument(
            "--output",
            default=".env.hqc",
            help="Output path (default: .env.hqc; keep this file private).",
        )

    def handle(self, *args, **options):
        output = Path(options["output"]).expanduser().resolve()
        if output.exists():
            raise CommandError(f"Refusing to overwrite existing key file: {output}")
        try:
            values = generate_hqc_keypair()
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
        output.chmod(0o600)
        self.stdout.write(self.style.SUCCESS(f"HQC keypair written to {output} (mode 0600)."))
        self.stdout.write("Configure these values as private service variables; never commit the file.")
