"""Unit tests for the Interactive Terminal UI (TUI) Wizard."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rich.console import Console

from foca_core.wizard import InteractiveWizard
import main


class TestInteractiveWizard(unittest.TestCase):
    """Test domain sanitization, validation, menu choices, and config generation."""

    def setUp(self) -> None:
        self.console = Console(record=True, width=100)
        self.wizard = InteractiveWizard(console=self.console)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sanitize_domain(self) -> None:
        """Verify URL and protocol stripping to extract raw hostname."""
        self.assertEqual(
            self.wizard.sanitize_domain("https://example.com/reports/audit.pdf"),
            "example.com",
        )
        self.assertEqual(
            self.wizard.sanitize_domain("http://sub.domain.org:8080/index.html"),
            "sub.domain.org",
        )
        self.assertEqual(
            self.wizard.sanitize_domain("example.com/files/"),
            "example.com",
        )
        self.assertEqual(
            self.wizard.sanitize_domain("https://user:pass@secure.corp.net/admin"),
            "secure.corp.net",
        )
        self.assertEqual(
            self.wizard.sanitize_domain("   WWW.TARGET.COM   "),
            "www.target.com",
        )
        self.assertEqual(self.wizard.sanitize_domain(""), "")

    def test_is_valid_domain(self) -> None:
        """Verify hostname and IP address validation."""
        self.assertTrue(self.wizard.is_valid_domain("example.com"))
        self.assertTrue(self.wizard.is_valid_domain("sub.target.co.uk"))
        self.assertTrue(self.wizard.is_valid_domain("company-portal.org"))
        self.assertTrue(self.wizard.is_valid_domain("192.168.1.100"))
        self.assertTrue(self.wizard.is_valid_domain("localhost"))

        self.assertFalse(self.wizard.is_valid_domain(""))
        self.assertFalse(self.wizard.is_valid_domain("not a domain"))
        self.assertFalse(self.wizard.is_valid_domain("domain..com"))
        self.assertFalse(self.wizard.is_valid_domain("300.300.300.300"))

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    @patch("foca_core.wizard.IntPrompt.ask")
    def test_mode_1_doc_scraper(
        self,
        mock_int_prompt: MagicMock,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test wizard execution for Mode 1: Document Metadata Scraper (FOCA Core)."""
        # Prompt sequence:
        # 1. mode -> "1"
        # 2. domain -> "https://example.com/docs"
        # 3. formats -> "1"
        # 4. output_dir -> "./foca_output"
        mock_prompt.side_effect = ["1", "https://example.com/docs", "1", "./foca_output"]
        mock_int_prompt.return_value = 25
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "documents")
        self.assertEqual(config["modules"], ["documents"])
        self.assertEqual(config["domain"], "example.com")
        self.assertIsNone(config["local_dir"])
        self.assertFalse(config["spider"])
        self.assertEqual(
            config["file_types"],
            ["pdf", "docx", "xlsx", "pptx", "jpg", "png"],
        )
        self.assertEqual(config["max_files"], 25)
        self.assertEqual(config["output_dir"], "./foca_output")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    def test_mode_2_dns_audit_skips_file_prompts(
        self,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 2: DNS & Mail Server Audit skips file download prompts."""
        # Prompt sequence:
        # 1. mode -> "2"
        # 2. domain -> "target.org"
        # 3. output_dir -> "./dns_out" (file formats & limits skipped)
        mock_prompt.side_effect = ["2", "target.org", "./dns_out"]
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "dns")
        self.assertEqual(config["modules"], ["dns"])
        self.assertEqual(config["domain"], "target.org")
        self.assertEqual(config["file_types"], [])
        self.assertEqual(config["max_files"], 0)
        self.assertEqual(config["output_dir"], "./dns_out")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    def test_mode_3_subdomains(
        self,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 3: Passive Subdomain Discovery."""
        mock_prompt.side_effect = ["3", "sub.target.org", "./sub_out"]
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "subdomains")
        self.assertEqual(config["modules"], ["subdomains"])
        self.assertEqual(config["domain"], "sub.target.org")
        self.assertEqual(config["output_dir"], "./sub_out")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    def test_mode_4_tech_stack(
        self,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 4: Web Tech & Security Headers."""
        mock_prompt.side_effect = ["4", "tech.target.org", "./tech_out"]
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "tech")
        self.assertEqual(config["modules"], ["tech"])
        self.assertEqual(config["domain"], "tech.target.org")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    def test_mode_5_whois(
        self,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 5: Domain Registration / Whois."""
        mock_prompt.side_effect = ["5", "whois.target.org", "./whois_out"]
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "whois")
        self.assertEqual(config["modules"], ["whois"])
        self.assertEqual(config["domain"], "whois.target.org")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    def test_mode_6_social(
        self,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 6: Social Media Profiles."""
        mock_prompt.side_effect = ["6", "social.target.org", "./social_out"]
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "social")
        self.assertEqual(config["modules"], ["social"])
        self.assertEqual(config["domain"], "social.target.org")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    @patch("foca_core.wizard.IntPrompt.ask")
    def test_mode_7_full_footprint(
        self,
        mock_int_prompt: MagicMock,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 7: Full Organization Footprint (All modules combined)."""
        mock_prompt.side_effect = ["7", "corp.target.org", "2", "./full_out"]
        mock_int_prompt.return_value = 50
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "all")
        self.assertEqual(
            config["modules"],
            ["documents", "dns", "subdomains", "tech", "whois", "social"],
        )
        self.assertEqual(config["domain"], "corp.target.org")
        self.assertEqual(config["file_types"], ["pdf", "docx", "xlsx", "pptx"])
        self.assertEqual(config["max_files"], 50)
        self.assertEqual(config["output_dir"], "./full_out")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    @patch("foca_core.wizard.IntPrompt.ask")
    def test_mode_8_local_directory(
        self,
        mock_int_prompt: MagicMock,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test Mode 8: Local Directory Document Audit with Custom Extensions."""
        local_dir = self.temp_dir.name
        # 1. mode -> "8"
        # 2. local dir path
        # 3. formats choice -> "4" (Custom)
        # 4. custom format input -> "pdf, xlsx"
        # 5. output_dir -> "./local_out"
        mock_prompt.side_effect = [
            "8",
            local_dir,
            "4",
            "pdf, xlsx",
            "./local_out",
        ]
        mock_int_prompt.return_value = 10
        mock_confirm.return_value = True

        config = self.wizard.run()

        self.assertIsNotNone(config)
        self.assertEqual(config["mode"], "local")
        self.assertEqual(config["modules"], ["documents"])
        self.assertEqual(config["domain"], "")
        self.assertIsNotNone(config["local_dir"])
        self.assertEqual(
            Path(config["local_dir"]).resolve(),
            Path(local_dir).resolve(),
        )
        self.assertFalse(config["spider"])
        self.assertEqual(config["file_types"], ["pdf", "xlsx"])
        self.assertEqual(config["max_files"], 10)
        self.assertEqual(config["output_dir"], "./local_out")

    @patch("foca_core.wizard.Confirm.ask")
    @patch("foca_core.wizard.Prompt.ask")
    @patch("foca_core.wizard.IntPrompt.ask")
    def test_preflight_rejection(
        self,
        mock_int_prompt: MagicMock,
        mock_prompt: MagicMock,
        mock_confirm: MagicMock,
    ) -> None:
        """Test user declining execution at Pre-Flight Review Card returns None."""
        mock_prompt.side_effect = ["1", "example.com", "1", "./foca_output"]
        mock_int_prompt.return_value = 25
        mock_confirm.return_value = False

        config = self.wizard.run()
        self.assertIsNone(config)

    @patch("foca_core.wizard.Prompt.ask")
    def test_keyboard_interrupt_handling(self, mock_prompt: MagicMock) -> None:
        """Test graceful exit on KeyboardInterrupt."""
        mock_prompt.side_effect = KeyboardInterrupt
        config = self.wizard.run()
        self.assertIsNone(config)

    @patch("foca_core.wizard.InteractiveWizard.run")
    def test_main_cli_invokes_wizard_when_no_args(self, mock_wizard_run: MagicMock) -> None:
        """Verify main.py triggers InteractiveWizard when no command-line arguments are given."""
        mock_wizard_run.return_value = None

        with patch.object(sys, "argv", ["main.py"]):
            exit_code = main.main()
            self.assertEqual(exit_code, 0)
            mock_wizard_run.assert_called_once()

    @patch("foca_core.wizard.InteractiveWizard.prompt_post_scan_action")
    @patch("main.run_pipeline")
    @patch("foca_core.wizard.InteractiveWizard.run")
    def test_main_cli_executes_pipeline_with_wizard_config(
        self,
        mock_wizard_run: MagicMock,
        mock_run_pipeline: MagicMock,
        mock_post_scan: MagicMock,
    ) -> None:
        """Verify main.py executes run_pipeline when wizard returns valid config and exits cleanly."""
        mock_wizard_run.return_value = {
            "mode": "documents",
            "modules": ["documents"],
            "domain": "example.com",
            "local_dir": None,
            "spider": False,
            "file_types": ["pdf"],
            "max_files": 20,
            "output_dir": "./custom_output",
        }
        mock_run_pipeline.return_value = 0
        mock_post_scan.return_value = "exit"

        with patch.object(sys, "argv", ["main.py"]):
            exit_code = main.main()
            self.assertEqual(exit_code, 0)
            mock_run_pipeline.assert_called_once_with(
                domain="example.com",
                local_dir=None,
                spider=False,
                deep=True,
                file_types=["pdf"],
                max_files=20,
                output_dir_str="./custom_output",
                json_mode=False,
                no_download=False,
                mode="documents",
                modules=["documents"],
            )
            mock_post_scan.assert_called_once_with("example.com")

    @patch("rich.prompt.Prompt.ask")
    def test_prompt_post_scan_action(self, mock_prompt: MagicMock) -> None:
        """Verify post scan choices map to proper action codes."""
        mock_prompt.return_value = "1"
        self.assertEqual(self.wizard.prompt_post_scan_action("example.com"), "run_module")

        mock_prompt.return_value = "2"
        self.assertEqual(self.wizard.prompt_post_scan_action("example.com"), "new_target")

        mock_prompt.return_value = "3"
        self.assertEqual(self.wizard.prompt_post_scan_action("example.com"), "show_reports")

        mock_prompt.return_value = "4"
        self.assertEqual(self.wizard.prompt_post_scan_action("example.com"), "exit")

    @patch("rich.prompt.Prompt.ask")
    def test_prompt_additional_module(self, mock_prompt: MagicMock) -> None:
        """Verify selecting another module returns proper config dictionary."""
        mock_prompt.return_value = "1"
        res = self.wizard.prompt_additional_module("target.com", "./output")
        self.assertIsNotNone(res)
        self.assertEqual(res["mode"], "social")
        self.assertEqual(res["modules"], ["social"])
        self.assertEqual(res["domain"], "target.com")


if __name__ == "__main__":
    unittest.main()
