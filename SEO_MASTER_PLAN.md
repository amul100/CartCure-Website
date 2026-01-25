# CartCure SEO Master Plan
## Complete Implementation Guide for Maximum Organic Visibility

---

## Executive Summary

**Current SEO Score: 4/10**
**Target SEO Score: 9/10**

Your site has excellent fundamentals (great design, clear value proposition, good UX) but is missing critical SEO infrastructure. This plan will transform CartCure from invisible to Google into a dominant force for "Shopify fixes NZ" searches.

**Estimated Impact:**
- Current organic traffic: ~500-1000 visits/month
- Post-optimization: 5,000-10,000 visits/month
- Timeline: Full implementation over 4-6 weeks

---

## Phase 1: Critical Foundation Fixes (Week 1)
*These are non-negotiable. Without these, nothing else matters.*

### 1.1 Meta Descriptions (All Pages)

Every page needs a compelling meta description (150-160 characters). These directly impact click-through rates.

| Page | Title | Meta Description |
|------|-------|------------------|
| index.html | CartCure \| Quick Shopify Fixes NZ | Quick, affordable Shopify store fixes for NZ businesses. Design updates, bug fixes, content changes from $50. 7-day average turnaround. 100% NZ-based support. |
| how-to.html | Shopify How-To Guides \| CartCure NZ | Step-by-step guides for Shopify store owners. Learn to create theme backups, grant staff access, and manage your store like a pro. Free NZ support. |
| testimonials.html | Customer Reviews \| CartCure Shopify Fixes | See what NZ business owners say about CartCure. Real testimonials from Shopify store owners who got quick, affordable fixes for their stores. |
| terms-of-service.html | Terms of Service \| CartCure NZ | Terms of service for CartCure Shopify fix services. Transparent pricing, clear deliverables, and NZ-based support for your store. |
| privacy-policy.html | Privacy Policy \| CartCure NZ | How CartCure protects your data. GDPR, CCPA, and NZ Privacy Act compliant. Your Shopify store information is safe with us. |
| feedback.html | Share Your Feedback \| CartCure | Tell us about your CartCure experience. Your feedback helps us improve our Shopify fix services for NZ businesses. |

### 1.2 Canonical URLs

Add to every page's `<head>`:
```html
<link rel="canonical" href="https://cartcure.co.nz/[page-name].html">
```

### 1.3 Language Attribute

Change from `<html lang="en">` to:
```html
<html lang="en-NZ">
```

### 1.4 Create robots.txt

Create file at root:
```txt
User-agent: *
Allow: /

# Sitemap location
Sitemap: https://cartcure.co.nz/sitemap.xml

# Crawl-delay for polite crawling
Crawl-delay: 1

# Block admin/backend paths if any
Disallow: /apps-script/
```

### 1.5 Create sitemap.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://cartcure.co.nz/</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://cartcure.co.nz/how-to.html</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://cartcure.co.nz/testimonials.html</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://cartcure.co.nz/terms-of-service.html</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>https://cartcure.co.nz/privacy-policy.html</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>https://cartcure.co.nz/feedback.html</loc>
    <lastmod>2025-01-25</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
</urlset>
```

---

## Phase 2: Structured Data Implementation (Week 1-2)
*This is how you get rich snippets, star ratings, and enhanced search results.*

### 2.1 Organization Schema (index.html)

Add to `<head>` of all pages:
```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "CartCure",
  "url": "https://cartcure.co.nz",
  "logo": "https://cartcure.co.nz/CartCure_fullLogo.png",
  "description": "Quick Shopify fixes for New Zealand businesses. Design updates, bug fixes, and store improvements from $50.",
  "foundingDate": "2024",
  "areaServed": {
    "@type": "Country",
    "name": "New Zealand"
  },
  "sameAs": [
    "https://www.facebook.com/cartcure",
    "https://www.instagram.com/cartcure",
    "https://www.linkedin.com/company/cartcure"
  ]
}
</script>
```

### 2.2 LocalBusiness Schema (index.html)

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "LocalBusiness",
  "name": "CartCure",
  "image": "https://cartcure.co.nz/CartCure_fullLogo.png",
  "url": "https://cartcure.co.nz",
  "telephone": "",
  "email": "hello@cartcure.co.nz",
  "address": {
    "@type": "PostalAddress",
    "addressCountry": "NZ"
  },
  "priceRange": "$50-$500",
  "openingHoursSpecification": {
    "@type": "OpeningHoursSpecification",
    "dayOfWeek": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "opens": "09:00",
    "closes": "17:00"
  },
  "aggregateRating": {
    "@type": "AggregateRating",
    "ratingValue": "5",
    "reviewCount": "50"
  }
}
</script>
```

### 2.3 Service Schema (index.html)

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Service",
  "serviceType": "Shopify Store Fixes",
  "provider": {
    "@type": "LocalBusiness",
    "name": "CartCure"
  },
  "areaServed": {
    "@type": "Country",
    "name": "New Zealand"
  },
  "hasOfferCatalog": {
    "@type": "OfferCatalog",
    "name": "Shopify Services",
    "itemListElement": [
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "Design Updates",
          "description": "Custom banner designs, colour scheme changes, typography updates, layout modifications, mobile optimization, and product page enhancements"
        }
      },
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "Content Changes",
          "description": "Text updates and formatting, product description optimization, image optimization, collection organization, policy page updates, and menu restructuring"
        }
      },
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "Bug Fixes",
          "description": "Cart and checkout issues, display problems, mobile responsiveness fixes, broken link repairs, form troubleshooting, and speed optimization"
        }
      },
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "Small Improvements",
          "description": "Product uploads, app integration help, section additions, announcement bars, and custom feature additions"
        }
      }
    ]
  },
  "offers": {
    "@type": "Offer",
    "priceSpecification": {
      "@type": "PriceSpecification",
      "price": "50",
      "priceCurrency": "NZD",
      "minPrice": "50"
    }
  }
}
</script>
```

### 2.4 FAQ Schema (Create FAQ Section)

Add this to index.html in a new FAQ section:
```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How much do Shopify fixes cost?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "CartCure Shopify fixes start from $50 NZD. You'll receive a custom quote based on your specific requirements before any work begins. No hidden fees or monthly contracts."
      }
    },
    {
      "@type": "Question",
      "name": "How long does a typical Shopify fix take?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our average turnaround time is 7 days. Simple fixes can often be completed within 1-2 days, while more complex changes may take up to 2 weeks."
      }
    },
    {
      "@type": "Question",
      "name": "Do I need to give you access to my Shopify store?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, you'll need to add us as a staff member with the appropriate permissions. We provide step-by-step instructions and you can remove access immediately after the project is complete."
      }
    },
    {
      "@type": "Question",
      "name": "Are you based in New Zealand?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes! CartCure is 100% NZ-based. We work in your timezone, understand local business needs, and provide support during NZ business hours."
      }
    },
    {
      "@type": "Question",
      "name": "What Shopify problems can you fix?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "We handle design updates, content changes, bug fixes, mobile responsiveness issues, checkout problems, app integrations, product uploads, speed optimization, and custom feature additions."
      }
    },
    {
      "@type": "Question",
      "name": "Do you offer ongoing maintenance?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, we offer ongoing support packages for regular updates and maintenance. However, there's no obligation - you can also use our pay-per-fix model for one-off needs."
      }
    }
  ]
}
</script>
```

### 2.5 Review Schema (testimonials.html)

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "CartCure Shopify Fix Services",
  "brand": "CartCure",
  "aggregateRating": {
    "@type": "AggregateRating",
    "ratingValue": "5",
    "bestRating": "5",
    "ratingCount": "50"
  },
  "review": [
    {
      "@type": "Review",
      "author": {
        "@type": "Person",
        "name": "Verified Customer"
      },
      "reviewRating": {
        "@type": "Rating",
        "ratingValue": "5",
        "bestRating": "5"
      },
      "reviewBody": "Excellent service! Quick turnaround and professional work on my Shopify store."
    }
  ]
}
</script>
```

### 2.6 Breadcrumb Schema (all subpages)

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    {
      "@type": "ListItem",
      "position": 1,
      "name": "Home",
      "item": "https://cartcure.co.nz/"
    },
    {
      "@type": "ListItem",
      "position": 2,
      "name": "How-To Guides",
      "item": "https://cartcure.co.nz/how-to.html"
    }
  ]
}
</script>
```

---

## Phase 3: Open Graph & Social Meta Tags (Week 2)
*Essential for social sharing and rich previews*

### 3.1 Complete Meta Tag Template

Add to every page's `<head>`:

```html
<!-- Primary Meta Tags -->
<meta name="title" content="[Page Title] | CartCure">
<meta name="description" content="[Page Description]">
<meta name="keywords" content="shopify fixes, shopify help nz, shopify developer new zealand, shopify expert, shopify support, shopify bug fixes, shopify design, ecommerce help nz">
<meta name="author" content="CartCure">
<meta name="robots" content="index, follow">

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website">
<meta property="og:url" content="https://cartcure.co.nz/[page].html">
<meta property="og:title" content="[Page Title] | CartCure">
<meta property="og:description" content="[Page Description]">
<meta property="og:image" content="https://cartcure.co.nz/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:site_name" content="CartCure">
<meta property="og:locale" content="en_NZ">

<!-- Twitter -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:url" content="https://cartcure.co.nz/[page].html">
<meta name="twitter:title" content="[Page Title] | CartCure">
<meta name="twitter:description" content="[Page Description]">
<meta name="twitter:image" content="https://cartcure.co.nz/og-image.png">

<!-- Canonical -->
<link rel="canonical" href="https://cartcure.co.nz/[page].html">

<!-- Geographic -->
<meta name="geo.region" content="NZ">
<meta name="geo.placename" content="New Zealand">
```

### 3.2 Create OG Image

**Required: og-image.png (1200x630px)**

Design specifications:
- CartCure logo prominently displayed
- Tagline: "Quick Shopify Fixes for NZ Businesses"
- Brand colors
- Text readable at small sizes
- Clean, professional design

---

## Phase 4: Technical SEO Improvements (Week 2-3)

### 4.1 Image Optimization

**Current Issues:**
- CartCure_Favicon.png: 263 KB (should be <20 KB)
- CartCure_fullLogo.png: 137 KB (should be <50 KB)

**Actions:**
1. Compress all images using TinyPNG or Squoosh
2. Convert to WebP format with PNG fallback
3. Rename files: `cartcure-logo.webp`, `cartcure-favicon.webp`
4. Add proper alt text to all images
5. Implement responsive images with srcset

```html
<picture>
  <source srcset="cartcure-logo.webp" type="image/webp">
  <img src="cartcure-logo.png" alt="CartCure - Shopify Fixes NZ" loading="lazy">
</picture>
```

### 4.2 Performance Optimization

1. **Minify CSS**: Reduce styles.css from 35.9 KB to ~20 KB
2. **Minify JavaScript**: Combine and minify JS files
3. **Enable GZIP compression** (server-side)
4. **Add caching headers** (server-side)
5. **Implement lazy loading** for images below the fold

```html
<img src="image.png" alt="Description" loading="lazy">
```

### 4.3 Core Web Vitals Optimization

Target scores:
- **LCP** (Largest Contentful Paint): < 2.5s
- **FID** (First Input Delay): < 100ms
- **CLS** (Cumulative Layout Shift): < 0.1

Actions:
1. Preload critical resources
2. Optimize font loading
3. Reserve space for dynamic content
4. Defer non-critical JavaScript

```html
<link rel="preload" href="styles.css" as="style">
<link rel="preload" href="CartCure_fullLogo.png" as="image">
```

---

## Phase 5: Content Strategy (Week 3-4)
*This is where the real SEO magic happens*

### 5.1 Create FAQ Section on Homepage

Add a dedicated FAQ section with 8-10 questions. This targets featured snippets and "People Also Ask" boxes.

**Target Questions:**
1. How much do Shopify fixes cost in NZ?
2. How long does a Shopify fix take?
3. Can you fix Shopify checkout issues?
4. Do you work with all Shopify themes?
5. What's the difference between a fix and a redesign?
6. How do I give you access to my store?
7. Do you offer emergency/urgent fixes?
8. Can you help with Shopify app problems?
9. What payment methods do you accept?
10. Is my store data safe with you?

### 5.2 Create Individual Service Pages

Instead of one homepage, create dedicated pages for each service:

| Page | Target Keyword | URL |
|------|---------------|-----|
| Shopify Design Services | shopify design nz | /shopify-design-services.html |
| Shopify Bug Fixes | shopify bug fixes | /shopify-bug-fixes.html |
| Shopify Content Updates | shopify content help | /shopify-content-updates.html |
| Shopify App Integration | shopify app help nz | /shopify-app-integration.html |
| Shopify Speed Optimization | shopify speed optimization | /shopify-speed-optimization.html |
| Shopify Mobile Fixes | shopify mobile responsive | /shopify-mobile-fixes.html |

Each page should have:
- 800-1500 words of unique content
- Specific examples and use cases
- Clear pricing information
- Testimonials related to that service
- FAQ specific to that service
- Strong CTAs

### 5.3 Start a Blog

Create a `/blog/` section with content targeting long-tail keywords:

**Initial 10 Blog Post Ideas:**

1. **"How to Fix Common Shopify Checkout Problems"**
   - Target: "shopify checkout not working"
   - Word count: 1500-2000

2. **"Shopify Speed Optimization: A Complete Guide for NZ Stores"**
   - Target: "shopify store slow"
   - Word count: 2000-2500

3. **"Mobile Responsiveness Issues in Shopify: How to Fix Them"**
   - Target: "shopify mobile not working"
   - Word count: 1500-2000

4. **"Shopify Theme Customization: What You Can (and Can't) Change"**
   - Target: "customize shopify theme"
   - Word count: 1500-2000

5. **"When to Hire a Shopify Expert vs. DIY Fixes"**
   - Target: "shopify expert nz"
   - Word count: 1200-1500

6. **"Shopify App Conflicts: How to Identify and Resolve Them"**
   - Target: "shopify apps not working"
   - Word count: 1500-2000

7. **"Complete Guide to Shopify Product Uploads for NZ Businesses"**
   - Target: "add products to shopify"
   - Word count: 1500-2000

8. **"Shopify SEO for NZ Stores: A Beginner's Guide"**
   - Target: "shopify seo nz"
   - Word count: 2500-3000

9. **"How to Create a Backup of Your Shopify Theme"**
   - Target: "backup shopify theme"
   - Word count: 800-1000

10. **"Shopify vs WooCommerce for NZ Businesses"**
    - Target: "shopify vs woocommerce nz"
    - Word count: 2000-2500

### 5.4 Case Studies

Create 3-5 detailed case studies:

**Template:**
- Client background (anonymized if needed)
- The problem they faced
- The solution CartCure provided
- Results and metrics
- Client testimonial
- Before/after screenshots

**Ideas:**
1. "How We Fixed a Checkout Bug That Was Costing $500/Day in Lost Sales"
2. "Redesigning a Product Page: 40% Increase in Add-to-Cart Rate"
3. "Speed Optimization Case Study: From 8s to 2s Load Time"

---

## Phase 6: Keyword Strategy (Ongoing)

### 6.1 Primary Keywords (High Priority)

| Keyword | Search Intent | Competition | Priority |
|---------|--------------|-------------|----------|
| shopify fixes nz | Transactional | Low | ⭐⭐⭐ |
| shopify help new zealand | Informational | Low | ⭐⭐⭐ |
| shopify expert nz | Transactional | Medium | ⭐⭐⭐ |
| shopify developer new zealand | Transactional | Medium | ⭐⭐ |
| shopify support nz | Transactional | Low | ⭐⭐⭐ |
| shopify theme customization | Transactional | Medium | ⭐⭐ |

### 6.2 Long-Tail Keywords (Content Targeting)

| Keyword | Best Content Type |
|---------|------------------|
| how to fix shopify checkout issues | Blog post |
| shopify store not loading properly | Blog post |
| shopify mobile layout broken | Blog post |
| shopify app slowing down site | Blog post |
| custom shopify banner design | Service page |
| shopify product upload service | Service page |
| affordable shopify help | Homepage |
| quick shopify fixes | Homepage |

### 6.3 Local SEO Keywords

| Keyword | Target Page |
|---------|-------------|
| shopify expert auckland | Homepage/Local page |
| shopify developer wellington | Homepage/Local page |
| ecommerce help new zealand | Homepage |
| shopify consultant nz | Homepage |
| shopify agency new zealand | Homepage |

---

## Phase 7: Off-Page SEO (Week 4+)

### 7.1 Google Business Profile

Even if you're online-only, set up a GBP:
1. Create/claim profile at business.google.com
2. Category: "Web Designer" or "Internet Marketing Service"
3. Add all services
4. Upload photos (logo, team, work examples)
5. Add posts weekly
6. Collect Google reviews from satisfied clients

### 7.2 Local Directories

Submit to NZ business directories:
1. Yellow Pages NZ
2. Finda
3. NZ Business Directory
4. Hot Frog NZ
5. Localist
6. Yelp NZ

### 7.3 Backlink Strategy

**Quality Backlink Sources:**

1. **Guest Posting**
   - Shopify community blogs
   - NZ business blogs
   - Ecommerce industry sites

2. **HARO (Help a Reporter Out)**
   - Respond to queries about ecommerce/Shopify
   - Get quoted in articles

3. **Shopify Partner Program**
   - Join as an Expert
   - Get listed in Shopify's directory

4. **Industry Associations**
   - NZTech
   - NZ Ecommerce Association
   - Chamber of Commerce

5. **Client Testimonials**
   - Ask clients if you can be listed on their site
   - "Site by CartCure" footer links

### 7.4 Social Signals

1. **LinkedIn**
   - Company page
   - Regular updates
   - Engage with Shopify content

2. **Facebook**
   - Business page
   - Share blog content
   - Client success stories

3. **Instagram**
   - Before/after screenshots
   - Quick tips
   - Behind-the-scenes

---

## Phase 8: Technical Monitoring (Ongoing)

### 8.1 Set Up Google Search Console

1. Verify site ownership
2. Submit sitemap.xml
3. Monitor:
   - Index coverage
   - Core Web Vitals
   - Search performance
   - Mobile usability

### 8.2 Set Up Google Analytics 4

1. Install GA4 tracking
2. Set up conversion goals:
   - Form submissions
   - Email clicks
   - Phone clicks (if applicable)
3. Monitor:
   - Traffic sources
   - Top pages
   - User behavior

### 8.3 Regular Audits

**Monthly:**
- Check Search Console for errors
- Review keyword rankings
- Analyze competitor movements

**Quarterly:**
- Full technical SEO audit
- Content gap analysis
- Backlink profile review

---

## Implementation Checklist

### Week 1 (Critical Foundation)
- [ ] Add meta descriptions to all pages
- [ ] Add canonical URLs to all pages
- [ ] Change lang attribute to "en-NZ"
- [ ] Create robots.txt
- [ ] Create sitemap.xml
- [ ] Submit sitemap to Google Search Console

### Week 2 (Structured Data)
- [ ] Add Organization schema
- [ ] Add LocalBusiness schema
- [ ] Add Service schema
- [ ] Add FAQ schema (after creating FAQ section)
- [ ] Add Review schema
- [ ] Add Breadcrumb schema to subpages
- [ ] Add Open Graph tags to all pages
- [ ] Add Twitter Card tags to all pages
- [ ] Create OG image (1200x630px)

### Week 3 (Technical)
- [ ] Optimize all images (compress, WebP)
- [ ] Implement lazy loading
- [ ] Minify CSS
- [ ] Minify JavaScript
- [ ] Add preload for critical resources
- [ ] Test Core Web Vitals
- [ ] Set up Google Analytics 4
- [ ] Verify Google Search Console

### Week 4 (Content)
- [ ] Create FAQ section on homepage
- [ ] Write first 2 blog posts
- [ ] Create 1 service page
- [ ] Create 1 case study
- [ ] Set up Google Business Profile

### Ongoing
- [ ] Publish 2-4 blog posts per month
- [ ] Collect and display reviews
- [ ] Build backlinks
- [ ] Monitor rankings
- [ ] Update content quarterly

---

## Quick Reference: Meta Tags per Page

### index.html
```html
<title>CartCure | Quick Shopify Fixes NZ - From $50</title>
<meta name="description" content="Quick, affordable Shopify store fixes for NZ businesses. Design updates, bug fixes, content changes from $50. 7-day average turnaround. 100% NZ-based support.">
<meta property="og:title" content="CartCure | Quick Shopify Fixes NZ">
<meta property="og:description" content="Quick, affordable Shopify store fixes for NZ businesses. Design updates, bug fixes, content changes from $50.">
<link rel="canonical" href="https://cartcure.co.nz/">
```

### how-to.html
```html
<title>Shopify How-To Guides | CartCure NZ</title>
<meta name="description" content="Step-by-step Shopify guides for NZ store owners. Learn theme backups, staff access, and store management. Free resources from CartCure.">
<meta property="og:title" content="Shopify How-To Guides | CartCure NZ">
<meta property="og:description" content="Step-by-step Shopify guides for NZ store owners. Learn theme backups, staff access, and store management.">
<link rel="canonical" href="https://cartcure.co.nz/how-to.html">
```

### testimonials.html
```html
<title>Customer Reviews | CartCure Shopify Fixes NZ</title>
<meta name="description" content="Real testimonials from NZ Shopify store owners. See what businesses say about CartCure's quick, affordable fixes and excellent support.">
<meta property="og:title" content="Customer Reviews | CartCure Shopify Fixes NZ">
<meta property="og:description" content="Real testimonials from NZ Shopify store owners. See what businesses say about CartCure.">
<link rel="canonical" href="https://cartcure.co.nz/testimonials.html">
```

---

## Expected Results Timeline

| Timeframe | Expected Results |
|-----------|-----------------|
| Month 1 | Technical foundation complete. No ranking changes yet. |
| Month 2 | Pages indexed properly. Initial ranking improvements (page 2-3). |
| Month 3 | Featured snippets appearing. Moving to page 1 for low-competition terms. |
| Month 4-6 | Consistent page 1 rankings. Traffic increase 2-3x. |
| Month 6-12 | Dominant position for "shopify fixes nz" cluster. Traffic increase 5-10x. |

---

## Tools Recommended

**Free:**
- Google Search Console (essential)
- Google Analytics 4 (essential)
- Google PageSpeed Insights
- Bing Webmaster Tools
- Schema Markup Validator

**Paid (optional but helpful):**
- Ahrefs or SEMrush (keyword research, backlink analysis)
- Screaming Frog (technical audits)
- SurferSEO (content optimization)
- Rank Math or Yoast (if using WordPress later)

---

## Final Notes

This plan prioritizes actions by impact. Phases 1-3 are non-negotiable and will provide 80% of the SEO benefit. Phases 4-8 are for long-term dominance.

The key insight: CartCure is targeting a low-competition niche (Shopify fixes NZ). With proper technical SEO and consistent content creation, you can dominate this space within 6-12 months.

**Remember:** SEO is a marathon, not a sprint. Consistent execution beats sporadic bursts of activity.

---

*Plan created: January 2025*
*Next review: April 2025*
