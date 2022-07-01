package tlv

import (
	"encoding/base64"
	"encoding/binary"
	"strconv"
)

//Tags is an array of parsed tags
type Tags map[TagType]Tag

//Tag is the TLV
type Tag struct {
	ID      uint16 `json:"type"` //type
	Name    string `json:"name,omitempty"`
	Length  uint16 `json:"length"`         //length
	Value   []byte `json:"value"`          //value
	SubTags Tags   `json:"tags,omitempty"` //sub tags
	Existed bool   `json:"existed,omitempty"`
}

func (tag Tag) GetSubTag(t TagType) Tag {
	if !tag.Existed {
		return Tag{
			Existed: false,
		}
	}

	return tag.SubTags.GetSubTag(t)
}

func (tags Tags) GetSubTag(t TagType) Tag {

	subTag := tags[t]

	if !subTag.Existed {
		return Tag{
			Existed: false,
		}
	}
	return subTag
}

func (tag Tag) String() string {

	if !tag.Existed {
		return "{ Tag not existed }"
	}
	ret := "{ Tag ID: " + strconv.Itoa(int(tag.ID))

	ret += " Tag Name: " + tag.Name
	if tag.Value != nil {
		ret += " Tag Value: " + base64.RawURLEncoding.EncodeToString(tag.Value)
	}

	for _, subTag := range tag.SubTags {
		ret += subTag.String()
	}

	return ret + " }"
}

func ParseBase64(b64 string) (Tags, error) {
	data, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

//Parse parses the data to tags
func Parse(data []byte) (Tags, error) {
	var tags = make(Tags)

	for len(data) > 0 {
		tag, err := parseTag(data)
		if err != nil {
			return tags, err
		}

		if 0x1000&tag.ID == 4096 {
			//recursive descent parsing
			subTags, err := Parse(tag.Value)
			if err != nil {
				return tags, err
			}

			tag.SubTags = subTags
		}

		tags[TagType(tag.ID)] = tag

		data = data[4+tag.Length:]
	}

	return tags, nil
}

//parseTLV takes a given bytes and parses with tlv structure
func parseTag(data []byte) (Tag, error) {
	t := data[:2]
	l := data[2:4]

	tagID := binary.LittleEndian.Uint16(t)
	tagLength := binary.LittleEndian.Uint16(l)

	if len(data)-4 < int(tagLength) {
		return Tag{}, ErrRangeException
	}

	var tagName string
	if name, ok := tags[TagType(tagID)]; ok {
		tagName = name
	} else {
		tagName = "TAG_UNKNOWN"
	}

	return Tag{
		ID:      tagID,
		Length:  tagLength,
		Value:   data[4 : tagLength+4],
		Name:    tagName,
		Existed: true,
	}, nil

	//A tag that has the 14th bit (0x2000) set indicates
	//that it is critical and a receiver must abort processing
	//the entire message if it cannot process that tag.
}
