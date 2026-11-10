// NEON NEXUS - Main JavaScript
(function() {
    'use strict';

    // Scroll-triggered animations
    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    document.addEventListener('DOMContentLoaded', function() {
        // Observe cards and sections for fade-in
        var animTargets = document.querySelectorAll('.card, .feature-card, .project-card, .section-title, .hero');
        animTargets.forEach(function(el) {
            el.classList.add('animate-on-scroll');
            observer.observe(el);
        });

        // Particles background effect
        var particlesEl = document.querySelector('.particles');
        if (particlesEl) {
            for (var i = 0; i < 30; i++) {
                var dot = document.createElement('span');
                dot.className = 'particle-dot';
                dot.style.left = Math.random() * 100 + 'vw';
                dot.style.top = Math.random() * 100 + 'vh';
                dot.style.animationDelay = (Math.random() * 5) + 's';
                dot.style.animationDuration = (3 + Math.random() * 4) + 's';
                particlesEl.appendChild(dot);
            }
        }

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
            anchor.addEventListener('click', function(e) {
                var target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });

        // Navbar scroll effect
        var nav = document.querySelector('.nav');
        if (nav) {
            window.addEventListener('scroll', function() {
                if (window.scrollY > 50) {
                    nav.classList.add('nav-scrolled');
                } else {
                    nav.classList.remove('nav-scrolled');
                }
            });
        }

        // Mobile menu toggle
        var navToggle = document.querySelector('.nav-toggle');
        var navLinks = document.querySelector('.nav-links');
        if (navToggle && navLinks) {
            navToggle.addEventListener('click', function() {
                navLinks.classList.toggle('open');
                navToggle.classList.toggle('active');
            });
        }

        // Typing effect for hero title
        var heroTitle = document.querySelector('.neon-title');
        if (heroTitle) {
            var text = heroTitle.textContent;
            heroTitle.textContent = '';
            var idx = 0;
            function typeChar() {
                if (idx < text.length) {
                    heroTitle.textContent += text.charAt(idx);
                    idx++;
                    setTimeout(typeChar, 50);
                }
            }
            setTimeout(typeChar, 300);
        }

        // Contact form submission
        var contactForm = document.querySelector('#contact-form');
        if (contactForm) {
            contactForm.addEventListener('submit', function(e) {
                e.preventDefault();
                var nameInput = contactForm.querySelector('input[name="name"]');
                var emailInput = contactForm.querySelector('input[name="email"]');
                var messageInput = contactForm.querySelector('textarea[name="message"]');
                var submitBtn = contactForm.querySelector('button[type="submit"]');
                var statusEl = document.querySelector('#contact-status');

                if (!statusEl) {
                    statusEl = document.createElement('div');
                    statusEl.id = 'contact-status';
                    statusEl.className = 'form-status';
                    contactForm.appendChild(statusEl);
                }

                var payload = {
                    name: (nameInput ? nameInput.value : '').trim(),
                    email: (emailInput ? emailInput.value : '').trim(),
                    message: (messageInput ? messageInput.value : '').trim()
                };

                if (!payload.name || !payload.email || !payload.message) {
                    statusEl.textContent = 'Пожалуйста, заполните все поля.';
                    statusEl.className = 'form-status form-status-error';
                    return;
                }

                if (submitBtn) submitBtn.disabled = true;
                statusEl.textContent = 'Отправка...';
                statusEl.className = 'form-status form-status-loading';

                fetch('/api/contact', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                })
                .then(function(resp) {
                    return resp.json().then(function(data) {
                        return { ok: resp.ok, data: data };
                    });
                })
                .then(function(result) {
                    if (result.ok && result.data.ok) {
                        statusEl.textContent = 'Сообщение отправлено! Спасибо.';
                        statusEl.className = 'form-status form-status-success';
                        if (nameInput) nameInput.value = '';
                        if (emailInput) emailInput.value = '';
                        if (messageInput) messageInput.value = '';
                    } else {
                        statusEl.textContent = (result.data && result.data.error) ? result.data.error : 'Ошибка отправки.';
                        statusEl.className = 'form-status form-status-error';
                    }
                })
                .catch(function(err) {
                    statusEl.textContent = 'Сетевая ошибка. Попробуйте снова.';
                    statusEl.className = 'form-status form-status-error';
                })
                .finally(function() {
                    if (submitBtn) submitBtn.disabled = false;
                });
            });
        }
    });
})();
