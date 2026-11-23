#!/usr/bin/env node
"use strict";

// tools/gen-brands-data.mjs — ONE-TIME build script for v3.2.0 (3P Matrix
// alignment §2). Not part of the regular per-release tooling (unlike
// update-lists.mjs/update-psl.mjs/build-top-sites-filter.mjs, which pull
// from a live upstream source) — this script's own source data is the
// curated table in claude/DESIGN_lookalike_check.md (copied inline below,
// verified by the 3P Matrix session against CrUX 202609 on 2026-10-19), so
// re-running it just reproduces the same data/Brands.json
// deterministically. Kept as a real script rather than a one-off throwaway
// because a correction/typo-fix later becomes "edit a table row here and
// re-run", not "hand-edit generated JSON".
//
// Merges three sources into one { keyword, domains, exceptions,
// wholeNameOnly } list, keyed by keyword:
//   1. SketchyUrlCheck.js's existing 113-entry BRANDS table.
//   2. BrandDomains.json's 22 entries (7 of which are not in the 113 —
//      chase, wellsfargo, citibank, ebay, binance, steampowered, outlook).
//   3. The DESIGN doc's regional extension (479 new real websites).
//
// Keyword derivation for a bare domain (2 and 3 above don't already have a
// keyword, just a real website): the domain's first label, lowercased,
// hyphens stripped (e.g. "credit-agricole.fr" -> "creditagricole",
// matching this project's existing convention — see SketchyUrlCheck.js's
// "schneiderelectric"/"bathandbodyworks" keywords for hyphenated/multi-word
// brand names). Where the SAME keyword recurs across countries (ing.nl,
// ing.de, ing.be, ing.pl all derive "ing"), the entries MERGE into one
// { keyword: "ing", domains: [ing.nl, ing.de, ing.be, ing.pl] } — this is
// exactly the "each brand with its real website(s)" shape the design doc
// asks for, and it's what makes a per-country-table transcription tractable
// at all: no hand-curation of ~479 individual keyword decisions.
//
// wholeNameOnly (doc §"Brand list"): true when the keyword is under 5
// letters (edit-distance/substring noise on short strings — same floor
// SketchyUrlCheck.js's FUZZY_MIN_BRAND_LENGTH already uses) OR is one of
// the doc's explicitly-named ordinary/common words. Those count only when
// the WHOLE registered name is the brand, never as a word buried inside a
// longer one.
//
// Shared-government-suffix domains (bare "gov.uk", "gov.pl", "gov.gr",
// "gob.mx", "gov.br" in the regional table) are deliberately EXCLUDED from
// the brand keyword list — they are not a brand name, just a suffix shared
// by thousands of unrelated agency sites. Per the doc, they are recognised
// as real sites, which here means: added to SHARED_GOV_SUFFIXES (consumed
// by tools/build-top-sites-filter.mjs §3 to union them into the top-sites
// list, not into Brands.json).
//
// Usage: node tools/gen-brands-data.mjs
//   writes data/Brands.json and data/GovSuffixes.json,
//   then runs gen-data-defaults.mjs to compile both into their .default.js.

import { writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { repoPaths } from "./repoPaths.mjs";

const { TOOLS_ROOT, EXT_ROOT } = repoPaths(import.meta.url);
const DATA_DIR = path.join(EXT_ROOT, "data");

// ── 1. The existing 113-entry BRANDS table (copied from SketchyUrlCheck.js
//    so this script has no runtime dependency on it — gen scripts are
//    build-time-only and this table rarely changes). keyword -> canonical.
const EXISTING_113 = [
    ["microsoft", "microsoft.com"], ["office", "office.com"], ["onedrive", "onedrive.com"],
    ["teams", "teams.microsoft.com"], ["google", "google.com"], ["gmail", "gmail.com"],
    ["googledrive", "drive.google.com"], ["apple", "apple.com"], ["icloud", "icloud.com"],
    ["amazon", "amazon.com"], ["paypal", "paypal.com"], ["bankofamerica", "bankofamerica.com"],
    ["hsbc", "hsbc.com"], ["revolut", "revolut.com"], ["blackrock", "blackrock.com"],
    ["mastercard", "mastercard.com"], ["visa", "visa.com"], ["americanexpress", "americanexpress.com"],
    ["jpmorganchase", "jpmorganchase.com"], ["usaa", "usaa.com"], ["nasdaq", "nasdaq.com"],
    ["coinbase", "coinbase.com"], ["shopify", "shopify.com"], ["meta", "meta.com"],
    ["facebook", "facebook.com"], ["instagram", "instagram.com"], ["netflix", "netflix.com"],
    ["spotify", "spotify.com"], ["linkedin", "linkedin.com"], ["youtube", "youtube.com"],
    ["pinterest", "pinterest.com"], ["nationalgeographic", "nationalgeographic.com"],
    ["adobe", "adobe.com"], ["dropbox", "dropbox.com"], ["docusign", "docusign.com"],
    ["slack", "slack.com"], ["zoominfo", "zoominfo.com"], ["airbnb", "airbnb.com"],
    ["booking.com", "booking.com"], ["logitech", "logitech.com"], ["fedex", "fedex.com"],
    ["dhl", "dhl.com"], ["ups", "ups.com"], ["johndeere", "johndeere.com"],
    ["nvidia", "nvidia.com"], ["qualcomm", "qualcomm.com"], ["amd", "amd.com"],
    ["cisco", "cisco.com"], ["geaerospace", "geaerospace.com"], ["schneiderelectric", "se.com"],
    ["nintendo", "nintendo.com"], ["playstation", "playstation.com"], ["roblox", "roblox.com"],
    ["riotgames", "riotgames.com"], ["ubisoft", "ubisoft.com"], ["bungie", "bungie.net"],
    ["toyota", "toyota.com"], ["bmw", "bmw.com"], ["mercedes", "mercedes-benz.com"],
    ["tesla", "tesla.com"], ["ferrari", "ferrari.com"], ["byd", "byd.com"],
    ["honda", "honda.com"], ["audi", "audi.com"], ["porsche", "porsche.com"],
    ["chanel", "chanel.com"], ["louisvuitton", "louisvuitton.com"], ["gucci", "gucci.com"],
    ["hermes", "hermes.com"], ["dior", "dior.com"], ["uniqlo", "uniqlo.com"],
    ["adidas", "adidas.com"], ["puma", "puma.com"], ["versace", "versace.com"],
    ["tiffany", "tiffany.com"], ["vans", "vans.com"], ["crocs", "crocs.com"],
    ["americaneagle", "ae.com"], ["costco", "costco.com"], ["nordstrom", "nordstrom.com"],
    ["footlocker", "footlocker.com"], ["sephora", "sephora.com"], ["glossier", "glossier.com"],
    ["homedepot", "homedepot.com"], ["maccosmetics", "maccosmetics.com"], ["lvmh", "lvmh.com"],
    ["mcdonalds", "mcdonalds.com"], ["cocacola", "coca-cola.com"], ["starbucks", "starbucks.com"],
    ["chipotle", "chipotle.com"], ["monsterenergy", "monsterenergy.com"], ["redbull", "redbull.com"],
    ["dunkin", "dunkin.com"], ["chickfila", "chick-fil-a.com"], ["traderjoes", "traderjoes.com"],
    ["innoutburger", "in-n-out.com"], ["baskinrobbins", "baskinrobbins.com"], ["ritzcarlton", "ritzcarlton.com"],
    ["marriott", "marriott.com"], ["hilton", "hilton.com"], ["bathandbodyworks", "bathandbodyworks.com"],
    ["lego", "lego.com"], ["colgate", "colgate.com"], ["johnsonjohnson", "jnj.com"],
    ["proctergamble", "pg.com"], ["hersheys", "hersheys.com"], ["unilever", "unilever.com"],
    ["headspace", "headspace.com"], ["peloton", "onepeloton.com"], ["philips", "philips.com"],
    ["bose", "bose.com"], ["7eleven", "7-eleven.com"], ["zoom", "zoom.us"],
];
const EXISTING_113_EXCEPTIONS = { zoom: ["zoominfo.com"] };

// ── 2. BrandDomains.json's 22 entries — the 7 not already in EXISTING_113.
const BRAND_DOMAINS_EXTRA = [
    "chase.com", "wellsfargo.com", "citibank.com", "ebay.com",
    "binance.com", "steampowered.com", "outlook.com",
];

// ── 3. Regional extension — every real website from the DESIGN doc's
//    table (claude/DESIGN_lookalike_check.md, "Regional brand list
//    (verified)"), flattened (country grouping doesn't matter for Brands.json
//    — every website ends up in one flat keyword-merged list regardless of
//    which country section it came from).
const REGIONAL_DOMAINS = `
ing.nl rabobank.nl abnamro.nl snsbank.nl asnbank.nl regiobank.nl knab.nl bunq.com triodos.nl
digid.nl belastingdienst.nl overheid.nl uwv.nl svb.nl duo.nl rdw.nl cjib.nl toeslagen.nl
postnl.nl bol.com coolblue.nl marktplaats.nl thuisbezorgd.nl ah.nl kpn.com ziggo.nl odido.nl
tikkie.me ideal.nl ns.nl eneco.nl vattenfall.nl essent.nl zalando.com vinted.com klarna.com
wise.com n26.com kbc.be belfius.be bpost.be itsme-id.com sparkasse.de deutschepost.de
deutsche-bank.de commerzbank.de dkb.de ing.de postbank.de comdirect.de vr.de elster.de
otto.de telekom.de vodafone.de o2online.de hermesworld.com dpd.de
credit-agricole.fr labanquepostale.fr societegenerale.fr boursobank.com lcl.fr caisse-epargne.fr
bnpparibas ameli.fr impots.gouv.fr franceconnect.gouv.fr ants.gouv.fr laposte.fr chronopost.fr
orange.fr sfr.fr free.fr bouyguestelecom.fr leboncoin.fr fnac.com cdiscount.com
bnpparibasfortis.be ing.be argenta.be proximus.be
post.lu spuerkeess.lu bil.com
bancosantander.es bbva.es caixabank.es bankinter.com bancsabadell.com agenciatributaria.gob.es
seg-social.es correos.es movistar.es elcorteingles.es
intesasanpaolo.com unicredit.it poste.it bancobpm.it agenziaentrate.gov.it inps.it tim.it
vodafone.it satispay.com finecobank.com
cgd.pt millenniumbcp.pt novobanco.pt portaldasfinancas.gov.pt ctt.pt mbway.pt
sparkasse.at raiffeisen.at bawag.at post.at oesterreich.gv.at bmf.gv.at
aib.ie bankofireland.com revenue.ie anpost.com ptsb.ie
pkobp.pl mbank.pl pekao.com.pl erste.pl ing.pl inpost.pl allegro.pl poczta-polska.pl gov.pl
swedbank.se seb.se handelsbanken.se nordea.se bankid.com skatteverket.se postnord.se
danskebank.dk mitid.dk borger.dk skat.dk postnord.dk mobilepay.dk
nordea.fi op.fi posti.fi vero.fi suomi.fi
csas.cz csob.cz kb.cz ceskaposta.cz
bancatransilvania.ro bcr.ro anaf.ro posta-romana.ro emag.ro
nbg.gr eurobank.gr alpha.gr piraeusbank.gr elta.gr gov.gr
otpbank.hu posta.hu
barclays.co.uk lloydsbank.com natwest.com santander.co.uk halifax.co.uk nationwide.co.uk
monzo.com gov.uk royalmail.com evri.com bt.com ee.co.uk
ubs.com postfinance.ch raiffeisen.ch post.ch twint.ch
dnb.no vipps.no posten.no skatteetaten.no
irs.gov ssa.gov usps.com capitalone.com discover.com usbank.com pnc.com truist.com
venmo.com zellepay.com cash.app att.com verizon.com t-mobile.com walmart.com target.com
bestbuy.com xfinity.com
rbc.com td.com scotiabank.com bmo.com cibc.com canadapost-postescanada.ca canada.ca
interac.ca desjardins.com rogers.com bell.ca
bbva.mx banorte.com banamex.com santander.com.mx sat.gob.mx gob.mx mercadolibre.com.mx telcel.com
itau.com.br bradesco.com.br bb.com.br caixa.gov.br nubank.com.br santander.com.br gov.br
correios.com.br mercadolivre.com.br magazineluiza.com.br picpay.com bancointer.com.br
bancogalicia.com.ar bna.com.ar mercadopago.com.ar arca.gob.ar santander.com.ar bbva.com.ar
bancoestado.cl santander.cl bancochile.cl sii.cl
bancolombia.com davivienda.com dian.gov.co nequi.com.co
viabcp.com bbva.pe interbank.pe sunat.gob.pe
commbank.com.au westpac.com.au anz.com nab.com.au my.gov.au ato.gov.au servicesaustralia.gov.au
auspost.com.au telstra.com.au optus.com.au woolworths.com.au coles.com.au aldi.com.au
thelott.com linkt.com.au afterpay.com
anz.co.nz asb.co.nz bnz.co.nz westpac.co.nz kiwibank.co.nz ird.govt.nz nzta.govt.nz
nzpost.co.nz spark.co.nz one.nz woolworths.co.nz paknsave.co.nz newworld.co.nz mylotto.co.nz
bk.mufg.jp smbc.co.jp mizuhobank.co.jp japanpost.jp jp-bank.japanpost.jp rakuten.co.jp
rakuten-card.co.jp nta.go.jp docomo.ne.jp au.com softbank.jp kuronekoyamato.co.jp
sagawa-exp.co.jp aeon.co.jp etc-meisai.jp mercari.com paypay.ne.jp saisoncard.co.jp jcb.co.jp
kbstar.com shinhan.com wooribank.com hanabank.com nonghyup.com kakaobank.com toss.im gov.kr
hometax.go.kr epost.go.kr cjlogistics.com coupang.com naver.com kakao.com kt.com tworld.co.kr
lguplus.com ssg.com lotteon.com dhlottery.co.kr
slsp.sk tatrabanka.sk posta.sk nlb.si posta.si pbz.hr zaba.hr posta.hr dskbank.bg econt.com
speedy.bg lhv.ee swedbank.ee eesti.ee omniva.ee swedbank.lv latvija.gov.lv swedbank.lt seb.lt
privatbank.ua monobank.ua diia.gov.ua novaposhta.ua ukrposhta.ua posta.rs islandsbanki.is
arionbanki.is island.is bov.com maltapost.com bankofcyprus.com
brou.com.uy itau.com.py pichincha.com bancodevenezuela.com jumbo.cl lider.cl exito.com plazavea.com.pe
banrural.com.gt bi.com.gt bancobcr.com bncr.fi.cr correos.go.cr banistmo.com bgeneral.com
bancoagricola.com ficohsa.com banreservas.com popularenlinea.com
dhl.com dhl.de ups.com fedex.com dpd.com gls-group.com gls-info.nl myhermes.de budbee.com
jumbo.com lidl.nl lidl.de lidl.com aldi.nl aldi.com aldi-nord.de aldi-sued.de plus.nl dirk.nl
picnic.app carrefour.fr carrefour.com leclerc delhaize.be colruyt.be rewe.de edeka.de kaufland.de
tesco.com sainsburys.co.uk asda.com morrisons.com kroger.com costco.com mercadona.es esselunga.it conad.it
nederlandseloterij.nl postcodeloterij.nl vriendenloterij.nl lotto.de euro-millions.com
national-lottery.co.uk fdj.fr loteriasyapuestas.es selae.es lottomatica.it powerball.com
megamillions.com calottery.com loterias.caixa.gov.br
albertsons.com safeway.com publix.com heb.com wholefoodsmarket.com aldi.us traderjoes.com
wegmans.com meijer.com instacart.com foodlion.com
aldi.co.uk lidl.co.uk waitrose.com coop.co.uk iceland.co.uk ocado.com
loblaws.ca sobeys.com metro.ca walmart.ca costco.ca realcanadiansuperstore.ca nofrills.ca pcoptimum.ca
walmart.com.mx soriana.com chedraui.com.mx oxxo.com
paodeacucar.com assai.com.br atacadao.com.br carrefour.com.br
coto.com.ar diaonline.supermercadosdia.com.ar
carrefour.es dia.es
coop.it carrefour.it
biedronka.pl zabka.pl
ica.se
netto.dk salling.dk
k-ruoka.fi s-kaupat.fi
continente.pt pingodoce.pt
billa.at spar.at
dunnesstores.com supervalu.ie
migros.ch coop.ch
rema.no
`.trim().split(/\s+/);

// Bare shared-government-suffix domains present in the table above — not a
// brand name, just a registration suffix shared by many unrelated agencies.
// Excluded from Brands.json keyword derivation; still a real, popular site
// for test 1 ("the site itself is popular -> stop"), so union them into
// the top-sites filter instead (see build-top-sites-filter.mjs §3).
const SHARED_GOV_SUFFIXES = [
    "gov.pl", "gov.gr", "gov.uk", "gob.mx", "gov.br", "gov.kr",
];

// Explicit ordinary/common-word keywords (doc §"Brand list") — count only
// when the WHOLE registered name is imitated, never as a word inside a
// longer one, regardless of length.
const ORDINARY_WORDS = new Set([
    "plus", "target", "free", "orange", "dirk", "bell", "post", "lotto",
    "metro", "iceland", "coop", "spar", "dia", "ica", "au", "one",
]);

const WHOLE_NAME_MIN_LENGTH = 5; // same floor as SketchyUrlCheck's FUZZY_MIN_BRAND_LENGTH

function deriveKeyword(domain) {
    const firstLabel = domain.split(".")[0];
    return firstLabel.toLowerCase().replace(/-/g, "");
}

// ── Merge everything into one Map<keyword, {keyword, domains:Set, exceptions:Set}>
const merged = new Map();

function addEntry(keyword, domain, exceptions = []) {
    if (!merged.has(keyword)) {
        merged.set(keyword, { keyword, domains: new Set(), exceptions: new Set() });
    }
    const entry = merged.get(keyword);
    entry.domains.add(domain);
    for (const ex of exceptions) entry.exceptions.add(ex);
}

for (const [keyword, canonical] of EXISTING_113) {
    addEntry(keyword, canonical, EXISTING_113_EXCEPTIONS[keyword] || []);
}
for (const domain of BRAND_DOMAINS_EXTRA) {
    addEntry(deriveKeyword(domain), domain);
}
for (const domain of REGIONAL_DOMAINS) {
    if (SHARED_GOV_SUFFIXES.includes(domain)) continue; // excluded — see above
    addEntry(deriveKeyword(domain), domain);
}

const brands = [...merged.values()]
    .map(({ keyword, domains, exceptions }) => {
        const wholeNameOnly = keyword.length < WHOLE_NAME_MIN_LENGTH || ORDINARY_WORDS.has(keyword);
        const out = { keyword, domains: [...domains].sort() };
        if (exceptions.size > 0) out.exceptions = [...exceptions].sort();
        if (wholeNameOnly) out.wholeNameOnly = true;
        return out;
    })
    .sort((a, b) => a.keyword.localeCompare(b.keyword));

writeFileSync(
    path.join(DATA_DIR, "Brands.json"),
    JSON.stringify(brands, null, 2) + "\n",
    "utf8"
);
writeFileSync(
    path.join(DATA_DIR, "GovSuffixes.json"),
    JSON.stringify(SHARED_GOV_SUFFIXES.sort(), null, 2) + "\n",
    "utf8"
);

const totalWebsites = brands.reduce((n, b) => n + b.domains.length, 0);
console.log(`  Brands.json written: ${brands.length} keywords, ${totalWebsites} websites`);
console.log(`  GovSuffixes.json written: ${SHARED_GOV_SUFFIXES.length} shared suffixes`);

execFileSync(process.execPath, [path.join(TOOLS_ROOT, "gen-data-defaults.mjs")], { stdio: "inherit" });
