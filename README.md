# NickGate

NickGate is an SSH gateway for Ergo IRC users. It lets you log in using your NickServ account—no Linux username or password required. Once you're in, it automatically launches whatever script or environment you configure.

> ⚠️ **Warning:** You should assume that this is a work in progress that's not been properly tested for security.

---

## ✨ What You Get

- **SSH access with your NickServ credentials**
- **No system account needed**
- **Proxy Protocol Support Baked-in**
- **Automatic logout if you try to drop to a shell** (Still a bit of a work in progress)
- **ForceCommand: Force the user into your own environment upon login**
- **ForceOnExit: Issue a command upon user disconnection**

---

## 🔐 How It Works

1. Connect via SSH on your configured port.
2. Enter your NickServ password when prompted.
3. If you're registered and authenticated, you'll be dropped into whatever script or environment is configured.
4. That’s it—no Linux account, no clutter.

---

## 🛠️ Notes for Developers

We use environment variables `$NICK` and `$PASS` to store login credentials in memory so they can be passed on to other scripts easily, additionally we set the variable `$REAL_IP` containg the IP address of the connecting client even when behind a proxy such as haproxy or sshl.

With the force command functionality, you're able to run a script of your choosing—this could be `weechat`, `irssi`, `tinyirc`, or something more custom.

These environment variables are how you'll pass login information to your IRC client of choice.

A quick note on configuration, the best notes on it will be in our example nickgate.conf in the repo but....
The `forceonexit` command is used to execute a command when the user disconnects from their session. It
allows NICK/username substitution with `#NICK` in the exit command.

This is useful if for example, you wish to force-kill a users tmux session upon disconnection.

---


NickGate is designed for **accessing shared tools**, not general server use.

---

## 💬 Need Help?

Join `#Development` on `irc.transirc.chat` or visit [https://transirc.chat](https://transirc.chat)
