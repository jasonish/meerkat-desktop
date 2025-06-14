# Application Icons

This directory contains the application icons for Meerkat Desktop.

## Creating a Meerkat Icon

To match the navbar branding (🦫), you need to create a meerkat icon. Here are the steps:

1. **Create or find a meerkat image**:

   - Use an AI image generator (like DALL-E, Midjourney, or Stable Diffusion) with a prompt like:
     "Cute meerkat face icon, flat design, orange and black colors, simple geometric shapes, app icon style"
   - Or find a royalty-free meerkat icon from sites like:
     - https://www.flaticon.com/
     - https://icons8.com/
     - https://thenounproject.com/

2. **Required icon sizes**:

   - `icon.png` - 1024x1024px (base icon)
   - `32x32.png` - 32x32px
   - `128x128.png` - 128x128px
   - `128x128@2x.png` - 256x256px
   - `icon.ico` - Windows icon (multi-resolution)
   - `icon.icns` - macOS icon (if needed)

3. **Color scheme**:

   - Primary: Suricata Orange (#ff6600)
   - Secondary: Dark (#1a1a1a)
   - Background: Transparent or white

4. **Tools to generate icons**:

   - Online: https://www.favicon-generator.org/
   - Command line: Use ImageMagick to resize:

     ```bash
     # From a 1024x1024 source image:
     convert icon.png -resize 32x32 32x32.png
     convert icon.png -resize 128x128 128x128.png
     convert icon.png -resize 256x256 128x128@2x.png

     # Generate Windows .ico file:
     convert icon.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico
     ```

5. **Alternative: Use Tauri Icon Generator**:
   ```bash
   npm install -g @tauri-apps/cli
   tauri icon path/to/your/icon.png
   ```
   This will generate all required icon sizes automatically.

## Current Icons

The current icons are placeholder icons. Replace them with your meerkat design to match the app branding.
