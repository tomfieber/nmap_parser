# nmap_parser
A very simple nmap parser to make the most tedious parts of reporting **LESS** tedious. 

I wrote this to make my own reporting a bit easier, but it's a general purpose nmap parser, so there's no proprietary information here. 

# Install
This tool doesn't require installation, but it does have a few dependencies. You can install the dependencies a couple different ways. 

## Method 1

```bash
git clone https://github.com/tomfieber/nmap_parser.git
cd nmap_parser/
python3 -m pip install -r requirements.txt
```

## Method 2

```bash
pip3 install argparse, termcolor, python-libnmap
```

# Usage
This tool takes one Nmap XML file as input. Usage is simple:

```bash
python3 nmapParse.py -f <FILE TO PARSE>
```

# TODO
There's still A LOT to do with this
- [X] Implement type checking to return an error if someone tries to parse a non XML file. Ehh...sort of. There's probably a better way to do this. 
- [X] ~~Implement more options ot only print selected sections~~ Done for now.
- [X] ~~Show all port details in a useable way~~ Sort of done. There are a few bugs left to work out...mostly relating to how Nmap service objects are structured. 
- [ ] Eventually build in a threaded port scanner with nmap integration to avoid having to load a separate XML file. 