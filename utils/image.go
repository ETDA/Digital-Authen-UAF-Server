package utils

import (
	"bytes"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"image"
	"image/color"
	"image/png"
)

func GetLabelImage(text string) (*image.RGBA, []byte) {
	img := image.NewRGBA(image.Rect(0, 0, 300, 100))
	addLabel(img, 20, 30, "Hello Go")
	buf := new(bytes.Buffer)
	_ = png.Encode(buf, img)
	return img, buf.Bytes()
}

func addLabel(img *image.RGBA, x, y int, label string) {
	col := color.RGBA{R: 200, G: 100, A: 255}
	point := fixed.Point26_6{X: fixed.Int26_6(x * 64), Y: fixed.Int26_6(y * 64)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}
