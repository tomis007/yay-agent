<p align="center">
<img src="resources/mascot.png" alt="Mascot" width="300"/>
</p>


<p align="center">
YAY-Agent is Yet Another Yubikey SSH Agent written in Golang.
</p>


<p align="center">
  <a href="#features">Features</a> •
  <a href="#description">Description</a> •
  <a href="#installation">Installation</a> •
  <a href="#getting started">Getting Started</a> •
  <a href="#usage">Usage</a> •
  <a href="#credits">Credits and Inspiration</a>
</p>


# Features
- **SSH Agent with your Yubikey**: Use your yubikey to store an ssh key for authentication!
- **Bring your yubikey to another computer and use it again**: No need to copy over the key, it's stored on the Yubikey's PIV Authentication slot!
- **The Yubikey PIN is stored with Memguard**: Powered by [memGuard](https://github.com/awnumar/memguard).
- **Helpful configuration utility**: Includes a configuration utility to set up your Yubikey!
- **Use your normal keys too**: Works just like the normal ssh-agent for ssh keys you might already have!

# Description
`yay-agent` is an SSH Agent with support for keys stored in a Yubikey's PIV Authentication slot (9A). It's very similar to FiloSottile's excellent [yubikey-agent](https://github.com/FiloSottile/yubikey-agent). You probably should just use that instead. The major differences are:
* PIN Caching - `yay-agent` caches the PIN after the initial unlock command.
* Yubikey 5.7.4 support - Works out of the box with newer Yubikey firmware.
* Not only Yubikey - `yay-agent` supports adding keys you already have with `ssh-key add -i ~/.ssh/id_rsa`.
* No exclusive lock - `yay-agent` lets you use your yubikey for other things while it's plugged in and running.

`yay-agent` is also similar to PIVY's [pivy-agent](https://github.com/arekinath/pivy#using-pivy-agent).

# Installation
## Releases
Download the statically linked binaries already compiled in the [Releases](https://github.com/tomis007/yay-agent/releases).

## Go Install
```bash
go install github.com/tomis007/yay-agent/cmd/yay-agent@latest
go install github.com/tomis007/yay-agent/cmd/yay-util@latest
```

## Build from source:
```bash
git clone git@github.com:tomis007/yay-agent.git && cd yay-agent
go build cmd/yay-agent/yay-agent.go
go build cmd/yay-util/yay-util.go
```

## Copy binaries to Path
```bash
# add to your path, for example:
sudo cp yay-agent /usr/local/bin/yay-agent
sudo cp yay-util /usr/local/bin/yay-util
```

# Getting Started
Like a normal `ssh-agent`, `yay-agent` needs to be running in the background. There are two options:

* systemd service - Use and enable the included systemd service (recommended method).
* login session - When `yay-agent` is started with the `--fork` option, it will output the required enviornment variables for configuration (less recommended method).

## Systemd Service
```bash
mkdir -p ~/.config/systemd/user
cp services/yay-agent.service ~/.config/systemd/user/yay-agent.service
systemctl daemon-reload --user
systemctl enable --user --now yay-agent.service

# required for Yubikey operations
sudo systemctl enable --now pcscd.service

# add to .zshrc or .bashrc
export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/yay-agent.sock
```

## Launchd (macOS)
```bash
cp services/yay-agent.plist ~/Library/LaunchAgents
launchctl load ~/Library/LaunchAgents/yay-agent.plist
launchctl kickstart gui/$(id -u)/com.github.yay-agent

# add to .zshrc or .bashrc
if [ -n "${SSH_YAYAUTH_SOCK}" ]; then
    export SSH_AUTH_SOCK_MACOS="${SSH_AUTH_SOCK}"
    export SSH_AUTH_SOCK="${SSH_YAYAUTH_SOCK}"
    unset SSH_YAYAUTH_SOCK
fi
```

## Login Session
When `yay-agent` is started with the `bind --fork` option, it will fork into the background and print out the necessary shell environment variables like `ssh-agent` does:
```bash
[user@localhost ]$ yay-agent bind --fork
SSH_AUTH_SOCK=/var/folders/hx/l08s9hpj5fs67dkp0qpyr06w0000gn/T/yay-3244068065/agent.87393; export SSH_AUTH_SOCK;
SSH_AGENT_ID=87393; export SSH_AGENT_PID;
echo Agent pid 87393
```

You can add the following to your shell (zsh or bash) to autostart the agent (for macOS change `XDG_RUNTIME_DIR` to something more appropriate):

```bash
# Add the following to your .bashrc or .zshrc
if ! pgrep -u "$USER" yay-agent > /dev/null; then
    yay-agent --bind --fork > "$XDG_RUNTIME_DIR/yay-agent.env"
fi
if [ ! -f "$SSH_AUTH_SOCK" ]; then
    source "$XDG_RUNTIME_DIR/yay-agent.env" >/dev/null
fi
```


## Yubikey Setup
Now that `yay-agent` is installed, the first step is to insert your Yubikey and run `yay-util config`. You'll be prompted to update your PIN, PUK, and the Management Key (which will be stored PIN protected on the Yubikey). If you already know what you're doing with your Yubikey feel free to skip this step.

```
[user@localhost yay-agent]$ yay-util  config
12:22PM INF Verifying Yubikey PIN. Not sure? Try default '123456'
Enter Yubikey PIN:
12:23PM INF Yubikey PIN verified!
12:23PM WRN Using default PIN!
Update PIN? (y/n): y

Enter New Yubikey PIN (6 - 8 digits):
Reenter:
12:23PM INF Updating PIN!
12:23PM WRN Using default PUK!
Update PUK? (y/n): Update PUK? (y/n): y

Enter new Yubikey PUK (8 digits):
Reenter:
12:23PM INF Updating PUK!
12:23PM WRN Using default Management Key!
Update Management Key? (y/n): y

12:23PM INF Updated management key! Saved on Yubikey as Metadata
```

With the Yubikey setup, create an SSH Key stored on the Yubikey (this will be stored in PIV's Authentication Slot 9A):
```bash
[user@localhost yay-agent]$ yay-util keys create
Enter Yubikey PIN:
12:34PM INF created ssh public key:
12:34PM INF ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsAa4pKs7CGbT7lQcv6UuxG+bsIv3rK5Vp8XeReaxe+
```

You can use `yay-util` to get additional information about the key:
```bash
[user@localhost yay-agent]$ yay-util keys keyinfo
12:35PM INF PublicKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsAa4pKs7CGbT7lQcv6UuxG+bsIv3rK5Vp8XeReaxe+
12:35PM INF Algorithm: Ed25519
12:35PM INF TouchPolicy: Always
12:35PM INF PinPolicy: Always
[user@localhost yay-agent]$ yay-util keys show
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsAa4pKs7CGbT7lQcv6UuxG+bsIv3rK5Vp8XeReaxe+ yayagent@31967083
```

## Using `yay-agent`
With our Yubikey properly configured, we can now use it! (ensure `yay-agent` is running as described earlier and `SSH_AUTH_SOCK` is properly set).

Before running any ssh key operation using our Yubikey, we need to submit the PIN to `yay-agent` with `yay-agent unlockpin`:
```bash
[user@localhost yay-agent]$ yay-agent pinstatus
12:42PM WRN Yubikey PIN is not verified!
[user@localhost yay-agent]$ yay-agent unlockpin
Enter Yubikey PIN:
12:43PM INF Yubikey PIN Set and Verified!
[user@localhost yay-agent]$ yay-agent pinstatus
12:43PM INF Yubikey PIN is valid and unlocked!
```

Then use the Yubikey as expected:
```bash
yay-util keys show >> ~/.ssh/authorized_keys
yay-util keys save

ssh -i yubikey.pub user@localhost
# Your yubikey will be blinking, touch it and log in !
```

## Normal Keys
You can also use normal keys:
```bash
# add your id_rsa to `yay-agent`
ssh-add ~/.ssh/id_rsa
# it works!
ssh user@server

# also using ssh-add -l to list keys
ssh-add -l
256 SHA256:cZbpt8F4WidSgMu7t9pI+594Cpn5Gddu5ngyP/P5HdI yubikey PIV SLOT 9A (ED25519)

```



# Usage

```
NAME:
   yay-agent - Yet Another Yubikey ssh agent

USAGE:
   yay-agent [global options] [command [command options]]

VERSION:
   0.4.0

COMMANDS:
   bind          start the agent listening on a UNIX-domain socket
   pinstatus     check the status of the yubikey pin, required to be unlocked for Yubikey operations to work
   unlockpin, X  submit the pin to the running agent
   lock, x       remove the pin from the running agent
   show          prints attached Yubikey's public key to stdout
   help, h       Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

```
NAME:
   yay-util - A yubikey helper to configure, manage, and create keys

USAGE:
   yay-util [global options] [command [command options]]

VERSION:
   0.4.0

COMMANDS:
   config   checks status of yubikey PIN and Management Key. Will help configure and change PIN, PUK, and Management Key
   piv      get yubikey piv information
   keys     Manage yubikey Authentication Key (Slot 9A)
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```


# Credits and Inspiration

* https://github.com/FiloSottile/yubikey-agent
* https://github.com/arekinath/pivy
* https://github.com/go-piv/piv-go
