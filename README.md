# PPLDump BOF

## Who worked on this?
- Justin Lucas  (@the_bit_diddler)
- Brad Campbell (@hackersoup)

## What is this?
Jokingly, an exercise of my own personal sanity maintenance.  In reality, this is a faithful porting of [@itm4n's](https://twitter.com/itm4n) `PPLDump` project.  

As one may imagine, this is a fully-fledged `BOF` to dump an arbitrary protected process.

## But, why?
The goal isn't the destination, but the journey.  Or that's what I told myself to make the endless suffering of this endeavor a bit less acute. :)

## Cool, but what are the requirements?
- [x] An administrative session of some kind
- [x] Knowledge of the `PPL` process ID (`PID`) you wish to dump
- [x] Currently residing in a 64-bit process
- [x] Currently residing on a `Windows 10` or greater endpoint

## What is this massive `fileheader.h` header, why so sus?
This is a one-to-one dump of the original resource file created during building the `PPLDump` project `DLL`, and you're more than welcome and encouraged to fact-check this.  As the original resource file was embedded (and therefore not usable due to a lack of linking for `Beacon Object Files`).  This was a way around that.  In the future, I may implement this ability to bring them arbitrarily, but use at your own risk.

## What do I need to know before doing anything?
- [x] You **MUST** change the `wcPID` varaible, found in `main.c` to be the same as your desired process ID. Seriously.
- [x] As a result, you **MUST** build this project from source *per endpoint* you wish to do this on.  There's a `Makefile`, just run it.
- [x] *Optionally*, you may change the location/name of the `dmp` file.  This is `DEFAULT_DUMP_FILE` in `src/headers/exploit.h`

## How do I run it?

1. Build the project via the `Makefile` in the `src` directory, ensuring again, that you have **ABSOLUTELY** changed the variable mentioned above.
2. Load the `Aggressor` `CNA` file in the `dist` directory.
3. Within your Beacon of choice (and one that meets the criteria): `ppldump YOUR_PROTECTED_PROCESS_PID`

## To-Do Items (if I have the time)
- [ ] Port more function calls to `syscalls`, but this is a very time-consuming process.
- [ ] Fix the unfortunate fail-pile of casting the desired process identifier to a `wchar_t*`.  Nothing I tried worked.
- [ ] Add support for a user-supplied DLL for other shenanigans.

