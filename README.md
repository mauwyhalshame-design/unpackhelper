# UnpackHelper

**UnpackHelper** أداة Pure Python للتحليل الساكن لبصمات برامج التغليف (packers) في ملفات Windows PE مثل `.exe` و`.dll`. لا تقوم الأداة بتشغيل الملف الذي تحلله، بل تقرأ ترويسة PE والأقسام وبعض العلامات النصية وتعرض النتيجة مع الأدلة ودرجة الثقة.

> النتيجة احتمالية وليست حكمًا على سلامة الملف أو كونه ضارًا.

## المتطلبات

- Python 3.9 أو أحدث.
- لا توجد مكتبات خارجية.
- تعمل على Windows وLinux وmacOS ما دام Python متوفرًا.
- تم تصميم التعامل مع المسارات باستخدام `pathlib` لتجنب افتراضات نظام تشغيل محدد.

## التشغيل

من داخل مجلد المشروع:

```bash
python main.py --help
python main.py --version
python main.py signatures
python main.py scan sample.exe
python main.py scan sample.exe --json
```

في Windows يمكن استخدام PowerShell أو CMD:

```powershell
py main.py scan C:\\path\\to\\sample.exe
```

```cmd
python main.py scan C:\\path\\to\\sample.exe
```

في Linux:

```bash
python3 main.py scan /path/to/sample.exe
```

يمكن تحديد مستوى السجل أو ملف إعدادات JSON:

```bash
python main.py --log-level INFO scan sample.exe
python main.py --config config.example.json scan sample.exe
```

## البصمات المضمنة

تتضمن النسخة الأولى قواعد لـ UPX وMPRESS وASPack وPECompact وThemida/WinLicense وVMProtect وFSG وEnigma Protector. أسماء الأقسام وحدها لا تعتبر دليلًا قاطعًا؛ لذلك تعرض الأداة الأدلة وتستخدم درجات ثقة.

## معالجة الأخطاء

تتعامل الأداة مع الملف غير الموجود، المسار غير الصحيح، الملفات الفارغة، الملفات غير التابعة لـ PE، الملفات المبتورة أو التالفة، عدم صلاحية القراءة، وملفات الإعدادات غير الصحيحة.

## الأمان

الأداة لا تنفذ الملفات ولا تستدعي برامج خارجية ولا تفك التغليف في الذاكرة. استخدمها مع ملفات اختبار معزولة، ولا تعتبر اكتشاف packer إثباتًا على أن الملف خبيث.

## هيكل المشروع

```text
unpackhelper/
├── main.py
├── cli.py
├── pe_parser.py
├── signatures.py
├── fingerprint.py
├── report.py
├── errors.py
├── config.py
└── tests/
    └── test_project.py
```

## الرخصة التعليمية

هذا المشروع نموذج تعليمي قابل للتوسعة. قبل استخدامه في بيئة إنتاجية، أضف عينات اختبار موثوقة، وسجّل الإصدارات، وراجع قواعد البصمات لتقليل النتائج الخاطئة.

## منطق الثقة

لا تعتبر الأداة وجود علامة واحدة إثباتًا نهائيًا. وجود marker فقط يعطي ثقة `Medium` كحد أقصى، بينما اجتماع marker مع اسم قسم مناسب ودرجة مرتفعة يعطي `High`. تعرض التقارير جميع الأدلة المستخدمة حتى يستطيع المحلل مراجعة سبب النتيجة.

مثال:

```text
Packer: UPX
Evidence: UPX!, UPX0, UPX1
Score: 100
Confidence: High
```

أما وجود `UPX!` وحده فينتج نتيجة قوية لكنها ليست قطعية، ويصنفها النظام `Medium` لتقليل النتائج الخاطئة.

## ملف الإعدادات

يوجد ملف `config.example.json` كنموذج. يمكن نسخه أو استخدامه مباشرة:

```bash
python main.py --config config.example.json scan sample.exe
```

الإعداد `max_file_size` يحدد الحد الأقصى لحجم الملف بالبايت، ويساعد على منع استهلاك غير متوقع للذاكرة أثناء التحليل.

## ملفات التوثيق

- `ARCHITECTURE.md`: يشرح معمارية المشروع ومسار البيانات ووظيفة كل ملف.
- `CHANGELOG.md`: يسجل التعديلات والأخطاء والإصلاحات ونتائج الاختبارات.
- `discussion_notes.md`: يحفظ ملاحظات الشرح والمناقشة خطوة بخطوة.

## التحليل الذكي وتقرير HTML

أضيفت وحدة `entropy.py` لحساب Shannon Entropy لكل قسم من أقسام PE. القيمة تقع بين 0 و8؛ وهي مؤشر إحصائي على عشوائية البيانات، وقد تساعد في الاشتباه بوجود ضغط أو تشفير، لكنها ليست حكمًا على أن الملف ضار.

لإنشاء تقرير HTML مستقل:

```bash
python main.py scan sample.exe --html report.html
```

يمكن فتح `report.html` في المتصفح. التقرير يعرض نوع الملف، SHA-256، packer المحتمل، مستوى الثقة، الأدلة، وجدول الأقسام مع Entropy وخصائص التنفيذ والكتابة. كما يعرض جدول Imports الذي يوضح DLL والوظائف المستوردة، وجدول Exports الذي يوضح الاسم والـ ordinal وRVA. لا يحتاج التقرير إلى مكتبات خارجية أو خادم ويب.

## Imports وExports

يقرأ `pe_parser.py` جدول Import Directory وExport Directory دون تشغيل الملف. يعرض Imports أسماء مكتبات Windows والوظائف المستوردة بالاسم أو بالـ ordinal، بينما يعرض Exports الوظائف التي يتيحها الملف للبرامج الأخرى. غياب Exports من ملف EXE أمر طبيعي غالبًا، كما أن وجود وظيفة مثل `VirtualAlloc` أو `CreateProcess` ليس دليلًا منفردًا على أن الملف ضار؛ تُستخدم هذه البيانات كقرائن مع البصمات وEntropy والتقييم البنيوي.

يعتمد التحويل من RVA إلى إزاحة داخل الملف على نطاقات الأقسام والتحقق من حدود البيانات. وعند عدم وجود دليل Import أو Export صالح، يعرض التقرير `0` أو `No ... found` بدل تحويل النتيجة إلى `Safe` تلقائيًا.

## فحص المجلد

لفحص كل الملفات داخل مجلد وجميع المجلدات الفرعية:

```bash
python main.py scan-dir Samples
```

يعرض الوضع النصي ملخصًا ثم تفاصيل ملفات PE فقط. الملفات الأخرى تُحسب في `Non-PE`، بينما تظهر الملفات التالفة في `Errors` والملفات المتجاوزة في `Skipped`.

لإيقاف البحث داخل المجلدات الفرعية:

```bash
python main.py scan-dir Samples --no-recursive
```

يمكن حفظ تقرير المجلد بصيغة JSON أو HTML:

```bash
python main.py scan-dir Samples --json --output folder_report.json
python main.py scan-dir Samples --html folder_report.html
```

## مقارنة ملفين

لمقارنة محتوى ملفين باستخدام SHA-256 فقط:

```bash
python main.py compare first.exe second.exe
```

تطابق القيم يعني تطابق البايتات، وليس أن الملفين آمنان.

## قاعدة التوقيعات الموسعة

تدعم قاعدة الكشف الآن مؤشرات محافظة لبرامج UPX وMPRESS وASPack وPECompact وThemida/WinLicense وVMProtect وFSG وEnigma Protector وNsPack وPetite وPEBundle وPELock وRLPack وNeolite وUPack وWWPack وYoda Protector.

كل قاعدة تفصل بين العلامات النصية وأسماء الأقسام، ولا تعتبر المؤشر المنفرد إثباتًا قطعيًا. تم توثيق مصادر اختيار البصمات وحدودها في `signature_research.md`.
