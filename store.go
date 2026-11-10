package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type SiteData struct {
	Hero        HeroSection      `json:"hero"`
	Services    []ServiceCard    `json:"services"`
	Projects    []ProjectCard    `json:"projects"`
	Gallery     []GalleryItem    `json:"gallery"`
	About       AboutSection     `json:"about"`
	Contact     ContactSection   `json:"contact"`
	Footer      FooterSection    `json:"footer"`
	Messages    []ContactMessage `json:"messages"`
	NavLinks    []NavLink        `json:"nav_links"`
	SiteTitle   string           `json:"site_title"`
	SiteTagline string           `json:"site_tagline"`
}

type HeroSection struct {
	Title      string `json:"title"`
	Subtitle   string `json:"subtitle"`
	ButtonText string `json:"button_text"`
	ButtonLink string `json:"button_link"`
	Image      string `json:"image"`
}

type ServiceCard struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Image       string `json:"image"`
}

type ProjectCard struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
	Link        string `json:"link"`
}

type GalleryItem struct {
	ID    string `json:"id"`
	Image string `json:"image"`
	Title string `json:"title"`
}

type AboutSection struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"`
}

type ContactSection struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Address     string `json:"address"`
}

type FooterSection struct {
	Copyright string `json:"copyright"`
	Links     string `json:"links"`
}

type NavLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type ContactMessage struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
	Date    string `json:"date"`
}

type AdminData struct {
	SiteData   SiteData
	NeedsSetup bool
	CsrfToken  string
}

// LoginView is the data passed to login.html / setup.html. The templates use
// {{if .Error}} so a plain error string can no longer be rendered — hence this
// small view struct that also carries the CSRF token for the form.
type LoginView struct {
	Error     string
	CsrfToken string
}

type Store struct {
	mu   sync.RWMutex
	path string
	data SiteData
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		s.data = defaultSiteData()
		if err := s.save(); err != nil {
			return nil, err
		}
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) GetAll() SiteData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Store) SaveAll(data SiteData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = data
	return s.save()
}

func (s *Store) AddMessage(msg ContactMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.Date == "" {
		msg.Date = time.Now().Format(time.RFC3339)
	}
	s.data.Messages = append(s.data.Messages, msg)
	return s.save()
}

func (s *Store) AddGalleryItem(item GalleryItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item.ID == "" {
		item.ID = genID()
	}
	s.data.Gallery = append(s.data.Gallery, item)
	return s.save()
}

func (s *Store) RemoveGalleryItem(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.data.Gallery {
		if g.ID == id {
			s.data.Gallery = append(s.data.Gallery[:i], s.data.Gallery[i+1:]...)
			return s.save()
		}
	}
	return nil
}

func (s *Store) save() error {
	tmp := s.path + ".tmp"
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func genID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func defaultSiteData() SiteData {
	return SiteData{
		SiteTitle:   "NEON NEXUS",
		SiteTagline: "Tomorrow's Technology, Today",
		NavLinks: []NavLink{
			{Label: "Home", URL: "/"},
			{Label: "Services", URL: "/services"},
			{Label: "Gallery", URL: "/gallery"},
			{Label: "About", URL: "/about"},
			{Label: "Contact", URL: "/contact"},
		},
		Hero: HeroSection{
			Title:      "Welcome to the NEON GRID",
			Subtitle:   "Experience the future of digital innovation through cyberpunk-inspired design and cutting-edge technology solutions.",
			ButtonText: "Explore Now",
			ButtonLink: "/services",
			Image:      "",
		},
		Services: []ServiceCard{
			{ID: genID(), Title: "Neural Interface Design", Description: "Custom brain-computer interface solutions for next-gen interaction.", Icon: "brain"},
			{ID: genID(), Title: "Cyber Security", Description: "Quantum-resistant encryption and penetration testing services.", Icon: "shield"},
			{ID: genID(), Title: "Holographic UX", Description: "Immersive 3D and holographic user experience design.", Icon: "eye"},
			{ID: genID(), Title: "AI Integration", Description: "Machine learning pipelines and neural network deployment.", Icon: "cpu"},
		},
		Projects: []ProjectCard{
			{ID: genID(), Title: "Project NIGHTWIRE", Description: "Neural-linked VR gaming platform with haptic feedback.", Image: "", Link: "#"},
			{ID: genID(), Title: "Project SYNTHWAVE", Description: "Music generation AI with cyberpunk aesthetic output.", Image: "", Link: "#"},
			{ID: genID(), Title: "Project GHOSTNET", Description: "Decentralized mesh network for privacy-first communications.", Image: "", Link: "#"},
		},
		Gallery: []GalleryItem{},
		About: AboutSection{
			Title:       "About NEON NEXUS",
			Description: "We are a collective of engineers, designers, and visionaries pushing the boundaries of technology in a neon-drenched digital frontier. Founded in the megacity of tomorrow, we build solutions for a world connected by light.",
			Image:       "",
		},
		Contact: ContactSection{
			Title:       "Jack Into Us",
			Description: "Ready to upgrade your digital reality? Send us a transmission.",
			Email:       "hello@neon-nexus.io",
			Phone:       "+1-555-NEON-01",
			Address:     "Sector 7, Night City, Neon District",
		},
		Footer: FooterSection{
			Copyright: "© 2024 NEON NEXUS. All rights reserved.",
			Links:     "",
		},
		Messages: []ContactMessage{},
	}
}
