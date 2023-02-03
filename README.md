# Password Trainer

This is a simple password trainer which stores hashed passwords and compares
them on training sessions.

This program comes with **absolutely no warranty**.
I am no security nor cryptography expert.
Please review the code yourself before entrusting it with your passwords.

## Usage

Make sure you have the dependencies from `./requirements.txt` installed.

```
$ ./pwdtrainer.py --help
```

The program will create a password database at the appropriate place in your
home folder.

## Dependencies

This program uses the following libraries:

- [_appdirs_](https://github.com/ActiveState/appdirs) under the
  [MIT License](https://github.com/ActiveState/appdirs/blob/master/LICENSE.txt)

## License

Copyright (C) 2021, 2023 Viktor Reusch

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
