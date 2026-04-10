import { useState, type ReactNode } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
    Plus,
    Minus,
    Shield,
    Download,
    FileQuestion,
    Mail,
    CheckCircle2,
    ArrowRight,
    Link,
} from "lucide-react";

function Navbar() {
    return (
        <nav className="flex items-center justify-between px-6 py-6 max-w-7xl mx-auto">
            <div className="flex items-center gap-2">
                <img
                    className="w-10 h-10"
                    src="logoRelyX.png"
                    alt="RelyX Logo"
                />{" "}
                <span className="text-2xl font-extrabold tracking-tight text-relyx-500">
                    RelyX
                </span>
            </div>
            <div className="hidden md:flex items-center gap-8 font-medium text-relyx-400">
                <a
                    href="#features"
                    className="hover:text-relyx-200 transition-colors"
                >
                    Features
                </a>
                <a
                    href="#compare"
                    className="hover:text-relyx-200 transition-colors"
                >
                    Compare
                </a>
                <a
                    href="#faq"
                    className="hover:text-relyx-200 transition-colors"
                >
                    FAQ
                </a>
            </div>
        </nav>
    );
}

function FeatureCard({
    title,
    icon,
    paragraph,
    delay,
}: {
    title: string;
    icon: ReactNode;
    paragraph: string;
    delay: number;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.5, delay }}
            whileHover={{ y: -8, transition: { duration: 0.2 } }}
            className="bg-white p-8 rounded-3xl border border-gray-100 shadow-xl shadow-gray-200/40 flex flex-col min-h-72 group"
        >
            <div className="bg-slate-50 w-16 h-16 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-relyx-200/10 transition-colors">
                {icon}
            </div>
            <h3 className="text-2xl font-bold text-relyx-500 mb-4 leading-tight">
                {title}
            </h3>
            <p className="text-gray-500 flex-grow text-sm md:text-base">
                {paragraph}
            </p>
        </motion.div>
    );
}

function CompareCard({
    title,
    description,
    delay,
}: {
    title: string;
    description: string;
    delay: number;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.5, delay }}
            whileHover={{ y: -8, transition: { duration: 0.2 } }}
            className="bg-white p-8 rounded-3xl border border-gray-100 shadow-xl shadow-gray-200/40 flex flex-col min-h-80 relative overflow-hidden"
        >
            <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-relyx-300 to-relyx-200" />
            <div className="flex items-center gap-3 mb-4 mt-2">
                <CheckCircle2 className="text-relyx-200 w-6 h-6 flex-shrink-0" />
                <h3 className="text-2xl font-bold text-relyx-500">{title}</h3>
            </div>
            <p className="text-gray-500 flex-grow text-sm md:text-base leading-relaxed">
                {description}
            </p>
        </motion.div>
    );
}

function FAQItem({ question }: { question: string }) {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div className="border-b border-gray-200/60 py-6">
            <button
                className="w-full flex items-center text-left text-xl md:text-2xl font-semibold text-relyx-500 hover:text-relyx-300 transition-colors gap-6 group"
                onClick={() => setIsOpen(!isOpen)}
            >
                <div className="flex-shrink-0 w-8 h-8 rounded-full border-2 border-relyx-200 flex items-center justify-center text-relyx-200 group-hover:bg-relyx-200 group-hover:text-white transition-all">
                    {isOpen ? (
                        <Minus size={18} strokeWidth={3} />
                    ) : (
                        <Plus size={18} strokeWidth={3} />
                    )}
                </div>
                {question}
            </button>
            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                    >
                        <p className="pt-6 pl-14 text-lg text-gray-600 leading-relaxed">
                            This is a placeholder answer for the FAQ. RelyX is
                            designed to keep you safe while browsing by
                            detecting and blocking malicious content before it
                            can harm your device or steal your data.
                        </p>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

export default function App() {
    const features = [
        {
            title: "URL detection",
            icon: <Shield className="text-relyx-200 w-8 h-8" />,
            paragraph:
                "Check if the URL which user hovered on is safe or not and gives a score based on how malicious it is and a reason that why it is malicious.",
        },
        {
            title: "Malicious download detection",
            icon: <Download className="text-relyx-200 w-8 h-8" />,
            paragraph:
                "If a user tries to download any malicious document, image, audio or video, the extension will first remind the user that it is malicious before downloading it on the system and give the score based on how malicious it is and why.",
        },
        {
            title: "Fake form detection",
            icon: <FileQuestion className="text-relyx-200 w-8 h-8" />,
            paragraph:
                " If a user tries to login, sign up or submit a fake or malicious form, the extension will first analyze the behaviour of form like - where is this form actually submitting data?, does the form action domain match the site domain?, are there hidden fields harvesting autofill data?, does this login form belong to a legitimate site? and remind the user and give the score of how malicious it is.",
        },
        {
            title: "Fake email and phishing attacks detection",
            icon: <Mail className="text-relyx-200 w-8 h-8" />,
            paragraph:
                "Check if an email is malicious or not and analyze phishing attacks and score it based on how malicious it is.",
        },
    ];

    const comparisons = [
        {
            title: "Guardio",
            description:
                "A leading Chrome security extension trusted by over 1.5 million users that proactively blocks malicious websites, thwarts phishing attempts, and stops harmful downloads before they reach your device. It also filters phishing threats in emails and texts. This is probably your closest competitor.",
        },
        {
            title: "Malwarebytes Browser Guard",
            description:
                "An incredibly popular antivirus-backed extension that blocks malicious websites so you don't accidentally download something harmful. It can also block ads and trackers and lets you easily enable or disable features from its main control panel.",
        },
        {
            title: "Bitdefender TrafficLight",
            description:
                "A completely free extension that provides real-time scanning on every page you visit to catch sites that become compromised over time. It blocks malicious web pages and phishing attempts and stays invisible during normal browsing - only showing up when it detects a threat.",
        },
    ];

    const comparisonTableRows = [
        {
            feature: "URL safety check",
            competitors: "✅ Database lookup",
            extension: "✅ AI scored + reason",
        },
        {
            feature: "New/unknown threats",
            competitors: "❌ Blind to them",
            extension: "✅ Behavior-based detection",
        },
        {
            feature: "Form analysis",
            competitors: "❌ Not done",
            extension: "✅ Real-time form scoring",
        },
        {
            feature: "Download blocking",
            competitors: "⚠️ After download",
            extension: "✅ Before download (intent)",
        },
        {
            feature: "Email phishing",
            competitors: "⚠️ App required",
            extension: "✅ Native in browser tab",
        },
        {
            feature: "Explains why",
            competitors: "❌ Just blocks",
            extension: "✅ Score + plain English reason",
        },
        {
            feature: "Graduated response",
            competitors: "❌ Binary block/allow",
            extension: "✅ Inform → Warn → Block",
        },
        {
            feature: "User education",
            competitors: "❌ None",
            extension: "✅ Built-in by design",
        },
    ];

    const faqs = [
        "How does RelyX protect my browsing?",
        "Is RelyX completely free to use?",
        "Does RelyX collect my personal data?",
        "How is RelyX different from other ad blockers?",
        "Can I use RelyX on mobile devices?",
        "Will RelyX slow down my browser?",
        "How often is the malicious database updated?",
    ];

    return (
        <div className="min-h-screen bg-relyx-100 selection:bg-relyx-200 selection:text-white">
            {/* Hero Section */}
            <div className="relative overflow-hidden bg-slate-50/50">
                <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-relyx-200/10 rounded-full blur-[120px] pointer-events-none" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-relyx-300/10 rounded-full blur-[100px] pointer-events-none" />

                <Navbar />

                <section className="relative pt-24 pb-32 px-6 text-center max-w-5xl mx-auto z-10">
                    <motion.h1
                        initial={{ opacity: 0, y: 30 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
                        className="text-6xl md:text-[5.5rem] font-extrabold tracking-tight text-relyx-500 mb-10 leading-[1.1]"
                    >
                        The extension that put{" "}
                        <br className="hidden md:block" />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-relyx-300 to-relyx-200">
                            safety first
                        </span>
                    </motion.h1>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6, delay: 0.2 }}
                        className="flex justify-center"
                    >
                        <button className="group bg-relyx-200 hover:bg-relyx-300 text-white font-bold py-5 px-12 rounded-full text-xl transition-all duration-300 hover:scale-105 shadow-xl shadow-relyx-200/30 flex items-center gap-3">
                            <a href="/extension.zip" download>
                                Download Now
                            </a>
                        </button>
                    </motion.div>
                </section>
            </div>

            {/* Features Section */}
            <section id="features" className="py-32 px-6">
                <div className="max-w-7xl mx-auto">
                    <motion.h2
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        className="text-4xl md:text-6xl font-extrabold text-center mb-20 text-relyx-500 tracking-tight"
                    >
                        Features of RelyX
                    </motion.h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                        {features.map((f, i) => (
                            <FeatureCard
                                key={i}
                                title={f.title}
                                icon={f.icon}
                                paragraph={f.paragraph}
                                delay={i * 0.1}
                            />
                        ))}
                    </div>
                </div>
            </section>

            {/* Download Instructions Section */}
            <section id="download-instructions" className="py-32 px-6 bg-white">
                <div className="max-w-7xl mx-auto">
                    <motion.h2
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        className="text-4xl md:text-6xl font-extrabold text-center mb-8 text-relyx-500 tracking-tight"
                    >
                        Download Instructions
                    </motion.h2>
                    <p className="text-center text-gray-600 text-lg md:text-xl max-w-3xl mx-auto mb-10">
                        Follow this guide to install the extension. You can view
                        the full PDF below or open it in a new tab.
                    </p>

                    <div className="flex justify-center mb-8">
                        <a
                            href="/README.pdf"
                            target="_blank"
                            rel="noreferrer"
                            className="group bg-relyx-200 hover:bg-relyx-300 text-white font-bold py-4 px-8 rounded-full text-lg transition-all duration-300 hover:scale-105 shadow-xl shadow-relyx-200/30 flex items-center gap-3"
                        >
                            Open PDF in New Tab
                            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                        </a>
                    </div>

                    <div className="w-full rounded-3xl border border-gray-100 shadow-xl shadow-gray-200/40 overflow-hidden bg-slate-50">
                        <iframe
                            src="/README.pdf"
                            title="RelyX Download Instructions PDF"
                            className="w-full h-[100vh] min-h-[540px]"
                        />
                    </div>
                </div>
            </section>

            {/* Comparison Section */}
            <section id="compare" className="py-32 px-6 bg-slate-50">
                <div className="max-w-7xl mx-auto">
                    <motion.h2
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        className="text-4xl md:text-6xl font-extrabold text-center mb-20 text-relyx-500 tracking-tight"
                    >
                        RelyX vs Other extensions
                    </motion.h2>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                        {comparisons.map((c, i) => (
                            <CompareCard
                                key={i}
                                title={c.title}
                                description={c.description}
                                delay={i * 0.1}
                            />
                        ))}
                    </div>

                    <div className="mt-12 overflow-hidden rounded-3xl border border-gray-100 bg-white shadow-xl shadow-gray-200/40">
                        <div className="overflow-x-auto">
                            <table className="w-full min-w-[760px]">
                                <thead className="bg-slate-50">
                                    <tr>
                                        <th className="px-6 py-4 text-left text-sm font-bold text-relyx-500 md:text-base">
                                            Feature
                                        </th>
                                        <th className="px-6 py-4 text-left text-sm font-bold text-relyx-500 md:text-base">
                                            Guardio / Norton / Bitdefender etc.
                                        </th>
                                        <th className="px-6 py-4 text-left text-sm font-bold text-relyx-500 md:text-base">
                                            RelyX
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {comparisonTableRows.map((row, idx) => (
                                        <tr
                                            key={row.feature}
                                            className={
                                                idx % 2 === 0
                                                    ? "bg-white"
                                                    : "bg-slate-50/40"
                                            }
                                        >
                                            <td className="px-6 py-4 text-sm font-semibold text-gray-800 md:text-base">
                                                {row.feature}
                                            </td>
                                            <td className="px-6 py-4 text-sm text-gray-600 md:text-base">
                                                {row.competitors}
                                            </td>
                                            <td className="px-6 py-4 text-sm font-semibold text-relyx-500 md:text-base">
                                                {row.extension}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </section>

            {/* Screenshots Section */}
            <section className="py-32 px-6 bg-relyx-400 text-white relative overflow-hidden">
                <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-white via-transparent to-transparent" />
                <div className="max-w-7xl mx-auto text-center relative z-10">
                    <motion.h2
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        className="text-4xl md:text-6xl font-extrabold mb-20 tracking-tight"
                    >
                        Screenshots of RelyX
                    </motion.h2>
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.6 }}
                        className="aspect-video bg-relyx-500/80 rounded-[2.5rem] border border-relyx-300/30 flex items-center justify-center shadow-2xl backdrop-blur-sm mx-auto max-w-5xl"
                    >
                        <img
                            src="/screenshot.png"
                            alt="RelyX Extension Screenshot"
                            className="w-full h-full object-cover rounded-[2.5rem] border border-relyx-300/30"
                        />
                    </motion.div>
                </div>
            </section>

            {/* FAQ Section */}
            <section id="faq" className="py-32 px-6 max-w-4xl mx-auto">
                <motion.h2
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-4xl md:text-6xl font-extrabold text-center mb-20 text-relyx-500 tracking-tight"
                >
                    FAQs
                </motion.h2>
                <div className="space-y-2">
                    {faqs.map((faq, i) => (
                        <FAQItem key={i} question={faq} />
                    ))}
                </div>
            </section>

            {/* Footer */}
            <footer className="bg-relyx-500 text-white pt-20 pb-10 px-6">
                <div className="max-w-7xl mx-auto">
                    <div className="flex flex-col md:flex-row justify-between items-center gap-8 mb-16">
                        <div className="flex items-center gap-3">
                            <Shield className="w-10 h-10 text-relyx-200" />
                            <span className="text-3xl font-extrabold tracking-tight">
                                RelyX
                            </span>
                        </div>
                        <div className="flex gap-8 text-lg font-medium text-relyx-200/80">
                            <a
                                href="#"
                                className="hover:text-white transition-colors"
                            >
                                Privacy Policy
                            </a>
                            <a
                                href="#"
                                className="hover:text-white transition-colors"
                            >
                                Terms of Service
                            </a>
                            <a
                                href="#"
                                className="hover:text-white transition-colors"
                            >
                                Contact
                            </a>
                        </div>
                    </div>
                    <div className="border-t border-relyx-400/50 pt-8 text-center md:text-left flex flex-col md:flex-row justify-between items-center gap-4">
                        <p className="text-relyx-200/60 text-lg">
                            &copy; 2026 RelyX. All rights reserved.
                        </p>
                        <p className="text-relyx-200/40">
                            The extension that put safety first.
                        </p>
                    </div>
                </div>
            </footer>
        </div>
    );
}
