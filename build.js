#!/usr/bin/env node
/**
 * Build script: Encrypts page content with AES-256-GCM.
 * Extracts lock screen from dev.html and encrypts the main content.
 * Compatible with Web Crypto API decryption in browser.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PASSWORD = 'Iranazadi';
const INPUT_FILE = path.join(__dirname, 'dev.html');
const OUTPUT_FILE = path.join(__dirname, 'index.html');
const ITERATIONS = 100000;

function encrypt(plaintext, password) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, encrypted, tag]);

    return {
        salt: salt.toString('base64'),
        data: combined.toString('base64')
    };
}

// ---- Main ----
console.log('🔐 Building encrypted page...');

const html = fs.readFileSync(INPUT_FILE, 'utf-8');

// 1. Extract <head> content (styles, fonts, tailwind)
const headMatch = html.match(/<head>([\s\S]*?)<\/head>/);
if (!headMatch) { console.error('❌ No <head> found'); process.exit(1); }
const headContent = headMatch[1];

// 2. Extract the lock screen HTML (from <div id="lock-screen" to its closing </div> before main-content)
const lockStart = html.indexOf('<!-- LOCK SCREEN -->');
const lockEnd = html.indexOf('<!-- MAIN CONTENT');
if (lockStart === -1 || lockEnd === -1) { console.error('❌ Could not find lock screen markers'); process.exit(1); }
const lockScreenHtml = html.substring(lockStart, lockEnd).trim();

// 3. Extract the step-navigation script (between first </script> and the IIFE)
const stepScriptMatch = html.match(/<script>\s*\/\/ ---- Step Navigation[\s\S]*?<\/script>/);
const stepScript = stepScriptMatch ? stepScriptMatch[0] : '';

// 4. Extract main content to encrypt (from <div id="main-content" to last </script> before </body>)
const mainStart = html.indexOf('<div id="main-content"');
const bodyEnd = html.indexOf('</body>');
// Find the last </script> before </body>
const beforeBody = html.substring(0, bodyEnd);
const lastScriptEnd = beforeBody.lastIndexOf('</script>') + '</script>'.length;

if (mainStart === -1 || lastScriptEnd <= 0) {
    console.error('❌ Could not find main-content');
    process.exit(1);
}

let contentToEncrypt = html.substring(mainStart, lastScriptEnd);

// Remove 'hidden' class so content shows after decryption
contentToEncrypt = contentToEncrypt.replace(
    '<div id="main-content" class="hidden">',
    '<div id="main-content">'
);

console.log(`  Content: ${contentToEncrypt.length.toLocaleString()} bytes`);

// 5. Encrypt
const encrypted = encrypt(contentToEncrypt, PASSWORD);
console.log(`  Encrypted: ${encrypted.data.length.toLocaleString()} bytes (base64)`);

// 6. Build output
const output = `<!DOCTYPE html>
<html lang="de">
<head>
${headContent}
</head>
<body class="bg-black text-white" style="font-family:'Inter',system-ui,sans-serif;">

    ${lockScreenHtml}

    <!-- Decrypted content injected here -->
    <div id="decrypted-content"></div>

    ${stepScript}

    <script>
    (function() {
        'use strict';

        var ED = {
            salt: '${encrypted.salt}',
            data: '${encrypted.data}'
        };

        // Lock screen particles
        (function() {
            var c = document.getElementById('lock-particles');
            if (!c) return;
            for (var i = 0; i < 40; i++) {
                var p = document.createElement('div');
                var star = Math.random() > 0.6;
                var sz = star ? (Math.random()*8+4) : (Math.random()*4+2);
                p.className = 'particle ' + (star ? 'particle-star' : 'particle-gold');
                p.style.cssText = 'width:'+sz+'px;height:'+sz+'px;left:'+(Math.random()*100)+'%;animation:fall '+(Math.random()*8+6)+'s linear infinite;animation-delay:'+(Math.random()*10)+'s;';
                c.appendChild(p);
            }
        })();

        window.bamLogout = function() {
            try {
                sessionStorage.removeItem(SESSION_KEY);
                sessionStorage.removeItem(SESSION_TS);
            } catch(e) {}
            location.reload();
        };

        function b64ToBytes(b64) {
            var bin = atob(b64);
            var bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
        }

        async function decrypt(password) {
            var enc = new TextEncoder();
            var saltBytes = b64ToBytes(ED.salt);
            var combined = b64ToBytes(ED.data);

            var keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
            );

            var key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: saltBytes, iterations: ${ITERATIONS}, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            var iv = combined.slice(0, 12);
            var ciphertext = combined.slice(12);

            var decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        }

        var SESSION_KEY = 'bam_pw';
        var SESSION_TS = 'bam_ts';
        var SESSION_TTL = 10 * 60 * 1000; // 10 minutes

        function savePw(pw) {
            try {
                sessionStorage.setItem(SESSION_KEY, pw);
                sessionStorage.setItem(SESSION_TS, Date.now().toString());
            } catch(e) {}
        }

        function getSavedPw() {
            try {
                var pw = sessionStorage.getItem(SESSION_KEY);
                var ts = parseInt(sessionStorage.getItem(SESSION_TS) || '0');
                if (pw && (Date.now() - ts) < SESSION_TTL) return pw;
                sessionStorage.removeItem(SESSION_KEY);
                sessionStorage.removeItem(SESSION_TS);
            } catch(e) {}
            return null;
        }

        function injectContent(html) {
            var ls = document.getElementById('lock-screen');
            if (ls) ls.remove();
            var container = document.getElementById('decrypted-content');
            container.innerHTML = html;

            Array.from(container.querySelectorAll('iframe')).forEach(function(oldIframe) {
                var newIframe = document.createElement('iframe');
                for (var i = 0; i < oldIframe.attributes.length; i++) {
                    var attr = oldIframe.attributes[i];
                    newIframe.setAttribute(attr.name, attr.value);
                }
                if (oldIframe.parentNode) oldIframe.parentNode.replaceChild(newIframe, oldIframe);
            });

            Array.from(container.querySelectorAll('script')).forEach(function(old) {
                var s = document.createElement('script');
                if (old.src) { s.src = old.src; }
                else { s.textContent = old.textContent; }
                if (old.parentNode) old.parentNode.replaceChild(s, old);
                else container.appendChild(s);
            });
        }

        var pwInput = document.getElementById('password-input');
        var enterBtn = document.getElementById('enter-btn');
        var errorMsg = document.getElementById('error-msg');

        async function tryUnlock() {
            var pw = pwInput.value;
            if (!pw) return;

            enterBtn.disabled = true;
            enterBtn.textContent = '...';

            try {
                var html = await decrypt(pw);
                savePw(pw);

                var ls = document.getElementById('lock-screen');
                ls.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
                ls.style.opacity = '0';
                ls.style.transform = 'scale(1.05)';

                setTimeout(function() { injectContent(html); }, 800);
            } catch(e) {
                pwInput.classList.add('shake');
                errorMsg.style.opacity = '1';
                pwInput.style.borderColor = 'rgba(239,68,68,0.5)';

                setTimeout(function() {
                    pwInput.classList.remove('shake');
                    pwInput.style.borderColor = 'rgba(255,215,0,0.3)';
                }, 600);
                setTimeout(function() { errorMsg.style.opacity = '0'; }, 3000);

                enterBtn.disabled = false;
                enterBtn.textContent = 'EINTRETEN';
            }
        }

        // Auto-unlock if password cached (< 10 min)
        var cached = getSavedPw();
        if (cached) {
            decrypt(cached).then(function(html) {
                injectContent(html);
            }).catch(function() {
                sessionStorage.removeItem(SESSION_KEY);
                sessionStorage.removeItem(SESSION_TS);
            });
        }

        enterBtn.addEventListener('click', tryUnlock);
        pwInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') tryUnlock(); });
    })();
    </script>
</body>
</html>`;

fs.writeFileSync(OUTPUT_FILE, output, 'utf-8');

console.log(`  Output: ${OUTPUT_FILE}`);
console.log(`  Size: ${output.length.toLocaleString()} bytes`);
console.log('✅ Done! index.html is ready for deployment.');
