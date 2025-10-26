# Parameter_Discovery_Tool
all type website Parameter Find

(![image](https://i.postimg.cc/fRWPPxHB/para.png)

```bash
git clone https://github.com/darkboss1bd/Parameter_Discovery_Tool.git
cd Parameter_Discovery_Tool
# Install dependencies
pip install -r requirements.txt
```

```bash
# Installation & Usage:
# Basic scan
python Parameter_Discovery_Tool.py -u https://example.com

# Advanced scan with spidering
python Parameter_Discovery_Tool.py -u https://example.com -s -t 15

# Scan multiple URLs from file
python Parameter_Discovery_Tool -f urls.txt -o results.txt

# Full professional scan
python Parameter_Discovery_Tool.py -u https://target.com -s -t 20 -o scan_results.txt
```
