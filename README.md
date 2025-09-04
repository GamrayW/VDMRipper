# VDM Ripper

Explore informations from Windows Defender VDM files

## vdmviewer

Display VDM file in a hex format, with colored sections to make it easier to read through it manually

```
$ python3 vdmviewer.py mpasbase.extracted
```
![](./img/basic_view.png)

You can manually specify Threats to include in the output:
```
$ python3 vdmviewer.py mpasbase.extracted -t "RaccoonWifi"
```
![](./img/named_threat.png)

> Note: `THREAT_BEGIN` is always in green and `THREAT_END` in red

You also can only filter specific signature types that you want to see (you can see the full list of current signatures types in the [json file](./sig_types.json))
```
$ python3 vmdviewer.py mpasbase.extracted -f SIGNATURE_TYPE_VFILE
``` 
![](./img/virtual_file.png)

> Here we dump the virtual files present during the defender emulation process

## vdmripper

Extract files from the VDM, **for now, only extraction of ASR LUA files and Virtual FS is supported**

```
python3 vdmripper.py mpasbase.extracted -e vfs
```
This extractd about 128 files from the virtual file system used during the emulation. I noticed that some known files used for evasion bypass are not present anymore (`aaa_TouchMeNot_.txt` for example)

![](./img/vfs.png)

```
python3 vdmripper.py mpasbase.extracted -e lua
```

This extracts 52k (at the time of writing the tool) Lua files used for the defender ASR ruling, they are stored in the following structure:
```
./output
	/threatname
		/<md5hash>.luac
		/<md5hash>.meta
```

The extraction of the mplua files is completed with the tool made by [Commial](https://github.com/commial/experiments/tree/master/windows-defender/lua) during his research on the topic that fixes the header of the file to make it readable by [luadec](https://github.com/viruscamp/luadec). You can automatically decompile the lua files by specifying the path of the luadec executable with `--luadec /path/to/binary`