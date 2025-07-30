
# Keyfy

```
---------------------------------------------------
 __ __      ______      __ __     ______    __ __  
/\ \/ /    /\  ___\   /\ \_\ \   /\ ___\   /\ \_\ \  
\ \  _"-.  \ \  __\   \ \____ \  \ \ __\   \ \____ \  
 \ \_\ \_\  \ \_____\  \/\_____\  \ \_\     \/\_____\  
  \/_/\/_/   \/_____/   \/_____/   \/_/      \/_____/
-----------------------------------------------------
```

Keyfy is a simple CLI password manager. Utilizes AES-GCM for password encryption coupled with PBKDF2 encryption key derivation from the master password. with both interactive mode and scripting capabilities. 


## Features
- Basic CRUD operations for the storage of credentials
- AES-GCM encryption with PBKDF2 derivation from the master password.
- Interactive and scripting mode.
## Installation
> This setup process defines a console script entry point for keyfy

1. Clone the repository
2. Navigate to the root directory
3. Either install it inside the local or global virtual environment.

### Locally
1. Activate the virtual environment
```zsh
source .venv/bin/actiavte
```

2. Install the application
```zsh
pip instal -e .
```

### Globally with `pipx`
Make sure `pipx` is installed. If you are using macOS and have brew installed you can run `brew install pipx`

```zsh
pipx install .
```

> **DB location.**
> - **macOS** `/Users/yourname/Library/Application Support/keyfy`
> - **Linux** `/home/yourname/.local/share/keyfy`
> - **Windows** `C:\Users\yourname\AppData\Local\keyfy`

## Usage
There are two ways to interactive with the application

### Interactive mode
Run this command in your terminal.
```zsh
keyfy interactive
```

### Scripting
Most commands are required to be authenticated therefore the username and password will always be required for each call.

It follows with this format.
```zsh
keyfy [OPTIONS] COMMAND [ARGS]...
```

Run keyfy `--help` to see all available commands.

For detailed parameter requirements of a specific command, use `--help` with that command. For example:
```zsh
keyfy store --help
```

**Example commands:**

Saving of key
```zsh
keyfy store myUsername myPassword key serviceUsername servicePassword
```

Retrieving the key
```zsh
keyfy store myUsername myPassword key
```

## Author

Antonio E. Olaguer II 

Github: [AntonioIIOlaguer](https://github.com/AntonioIIOlaguer)

Email: antonio.olaguer.ii@gmail.com
