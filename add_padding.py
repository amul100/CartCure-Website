from PIL import Image

# Load the image
img_path = 'CartCure_Favicon - padded.png'
img = Image.open(img_path)

# Add padding (increase by this many pixels on each side)
padding = 40  # pixels to add on each side

# Calculate new dimensions
new_width = img.size[0] + (padding * 2)
new_height = img.size[1] + (padding * 2)

# Create new image with transparent background
if img.mode == 'RGBA':
    new_img = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 0))
else:
    img = img.convert('RGBA')
    new_img = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 0))

# Paste original image in center
new_img.paste(img, (padding, padding), img)

# Save the result
output_path = 'CartCure_Favicon - padded.png'
new_img.save(output_path, 'PNG')
