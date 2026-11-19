import os
import zipfile
import fitz
from pathlib import Path
from PIL import Image, PngImagePlugin

sample_dir = Path("./sample_documents")
sample_dir.mkdir(parents=True, exist_ok=True)

# 1. PDF
pdf_path = sample_dir / "Quarterly_Security_Audit.pdf"
doc = fitz.open()
page = doc.new_page()
page.insert_text((50, 72), "Internal Security Review & Infrastructure Audit Report\nAuthor: Dr. Robert Vance\nDepartment: SecOps\nNetwork Share: \\\\fs01.corp.internal\\SecOps\\Audits\\2026\\")
doc.set_metadata({
    "title": "Internal Security Review & Infrastructure Audit",
    "author": "Dr. Robert Vance",
    "creator": "Adobe InDesign 2026 (Windows)",
    "producer": "Adobe PDF Library 18.5",
    "subject": "Enterprise Threat Intelligence",
    "keywords": "secops, audit, confidential, pci-dss"
})
doc.save(str(pdf_path))
doc.close()

# 2. DOCX
docx_path = sample_dir / "Network_Architecture_v2.docx"
core_xml = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:title>Global Network Architecture &amp; Segmentation</dc:title><dc:creator>Johnathan Reed</dc:creator><cp:lastModifiedBy>admin_service</cp:lastModifiedBy><dcterms:created>2026-04-12T09:15:00Z</dcterms:created><dcterms:modified>2026-04-15T14:22:00Z</dcterms:modified><dc:description>Confidential internal network map and gateway routes</dc:description></cp:coreProperties>'

app_xml = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft Office Word for Windows</Application><AppVersion>16.0000</AppVersion><Company>Defense Cybernetics Global</Company><Manager>Director Sarah Connor</Manager><Template>C:\\Users\\jreed\\AppData\\Roaming\\Microsoft\\Templates\\Corporate_Secure.dotx</Template></Properties>'

with zipfile.ZipFile(docx_path, "w") as zf:
    zf.writestr("docProps/core.xml", core_xml)
    zf.writestr("docProps/app.xml", app_xml)
    zf.writestr("word/document.xml", b"<w:document><w:body><w:p><w:r><w:t>Confidential network diagram.</w:t></w:r></w:p></w:body></w:document>")

# 3. XLSX
xlsx_path = sample_dir / "Infrastructure_Budget_2026.xlsx"
xl_core_xml = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Enterprise Infrastructure Cloud Allocation</dc:title><dc:creator>Samantha Hayes</dc:creator><cp:lastModifiedBy>finance_controller</cp:lastModifiedBy></cp:coreProperties>'

xl_app_xml = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft Excel 2026</Application><Company>Defense Cybernetics Global</Company></Properties>'

with zipfile.ZipFile(xlsx_path, "w") as zf:
    zf.writestr("docProps/core.xml", xl_core_xml)
    zf.writestr("docProps/app.xml", xl_app_xml)
    zf.writestr("xl/workbook.xml", b"<workbook/>")

# 4. PNG
png_path = sample_dir / "Server_Topology.png"
img = Image.new("RGB", (100, 100), color=(30, 40, 50))
meta = PngImagePlugin.PngInfo()
meta.add_text("Author", "Network Engineer Dave")
meta.add_text("Software", "Snagit 2026")
meta.add_text("Host", "CORP-DESKTOP-892")
img.save(str(png_path), pnginfo=meta)

print("Sample documents created successfully in", sample_dir.resolve())
