# NickGate

NickGate is an SSH gateway for Ergo IRC users. It lets you log in using your NickServ account—no Linux username or password required. Once you're in, it automatically launches whatever script or environment you configure.

> ⚠️ **Warning:** You should assume that this is a work in progress that's not been properly tested for security.

---

## ✨ What You Get

- **SSH access with your NickServ credentials**
- **No system account needed**
- **Automatic logout if you try to drop to a shell** (Still a bit of a work in progress)

---

## 🔐 How It Works

1. Connect via SSH on your configured port.
2. Enter your NickServ password when prompted.
3. If you're registered and authenticated, you'll be dropped into whatever script or environment is configured.
4. That’s it—no Linux account, no clutter.

---

## ✅ Requirements

- You must have a registered NickServ account on an Ergo IRC server with the API enabled.
- Your password must be correct—authentication is done in real time via NickServ.

---

NickGate is designed for **accessing shared tools**, not general server use.

---

## 💬 Need Help?

Join `#Development` on `irc.transirc.chat` or visit [https://transirc.chat](https://transirc.chat)
