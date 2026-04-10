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
} from "lucide-react";

function Navbar() {
    return (
        <nav className="flex items-center justify-between px-6 py-6 max-w-7xl mx-auto">
            <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-relyx-200" />
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
    delay,
}: {
    title: string;
    icon: ReactNode;
    delay: number;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.5, delay }}
            whileHover={{ y: -8, transition: { duration: 0.2 } }}
            className="bg-white p-8 rounded-3xl border border-gray-100 shadow-xl shadow-gray-200/40 flex flex-col h-72 group"
        >
            <div className="bg-slate-50 w-16 h-16 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-relyx-200/10 transition-colors">
                {icon}
            </div>
            <h3 className="text-2xl font-bold text-relyx-500 mb-4 leading-tight">
                {title}
            </h3>
            <p className="text-gray-500 flex-grow"></p>
        </motion.div>
    );
}

function CompareCard({ title, delay }: { title: string; delay: number }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.5, delay }}
            whileHover={{ y: -8, transition: { duration: 0.2 } }}
            className="bg-white p-8 rounded-3xl border border-gray-100 shadow-xl shadow-gray-200/40 flex flex-col h-64 relative overflow-hidden"
        >
            <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-relyx-300 to-relyx-200" />
            <div className="flex items-center gap-3 mb-6 mt-2">
                <CheckCircle2 className="text-relyx-200 w-6 h-6" />
                <h3 className="text-2xl font-bold text-relyx-500">{title}</h3>
            </div>
            <p className="text-gray-500 flex-grow"></p>
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
        },
        {
            title: "Malicious download detection",
            icon: <Download className="text-relyx-200 w-8 h-8" />,
        },
        {
            title: "Fake form detection",
            icon: <FileQuestion className="text-relyx-200 w-8 h-8" />,
        },
        {
            title: "Fake email and phishing attacks detection",
            icon: <Mail className="text-relyx-200 w-8 h-8" />,
        },
    ];

    const comparisons = [{ title: "xyz" }, { title: "xyz" }, { title: "xyz" }];

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
                            Download RelyX
                            <ArrowRight className="w-6 h-6 group-hover:translate-x-1 transition-transform" />
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
                                delay={i * 0.1}
                            />
                        ))}
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
                                delay={i * 0.1}
                            />
                        ))}
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
                        <div className="flex flex-col items-center gap-4">
                            <Shield className="w-16 h-16 text-relyx-300 opacity-50" />
                            <span className="text-relyx-200/80 text-2xl font-medium">
                                Screenshot Placeholder
                            </span>
                        </div>
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
