# مصادر بحث بصمات PE Packers

## المصادر

1. Detect It Easy الرسمي: https://www.detectiteasy.com/
   يوضح أن أدوات تحليل الملفات تستخدم signature-based detection مع heuristic analysis، وأنها تتعرف على packers وprotectors مثل UPX وASPack وPECompact وThemida وVMProtect وEnigma Protector. يجب التعامل مع أرقام التغطية الواردة في الصفحة بحذر لأنها تتغير مع تحديثات قاعدة البيانات.

2. Hexacorn، PE Section names – re-visited: https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
   يسرد مؤشرات أسماء أقسام مرتبطة بأدوات متعددة، منها: `.aspack` و`.adata` لـ ASPack/Armadillo، `FSG!` لـ FSG، `.enigma1` و`.enigma2` لـ Enigma Protector، `.MPRESS1` و`.MPRESS2` لـ MPRESS، `.nsp0` و`.nsp1` و`.nsp2` لـ NsPack، `.pec1` إلى `.pec6` و`PECompact2` لـ PECompact، `.petite` لـ Petite، `Themida` و`.winlice` لـ Themida/WinLicense، `UPX0` و`UPX1` و`UPX2` و`UPX!` لـ UPX، و`.vmp0` و`.vmp1` و`.vmp2` لـ VMProtect.

   المصدر نفسه يحذر ضمنيًا من تنوع أسماء الأقسام؛ لذلك لا ينبغي استخدام اسم القسم وحده كدليل قطعي.

3. pefile / peutils.py: https://github.com/erocarrera/pefile/blob/master/peutils.py
   يوضح نموذجًا معروفًا لقاعدة PEiD signatures، ويفرق بين signatures عند نقطة الدخول، signatures في بداية الأقسام، والبحث العام. هذا يدعم قرار جعل توقيعات نقطة الدخول أو بداية القسم أقوى من تطابق نص عشوائي في كامل الملف.

4. ANY.RUN، Basic Malware Packers: https://any.run/cybersecurity-blog/malware-packers-explained/
   يشرح الفرق بين archivers مثل ZIP/SFX وبين executable packers مثل UPX، ويذكر أن `UPX0` و`UPX1` و`UPX!` مؤشرات شائعة لفحص UPX. كما يؤكد أن استخدام packer لا يعني وحده أن الملف خبيث.

## قرار قاعدة المشروع

ستضاف توقيعات محافظة ومصنفة إلى marker وsection، مع أوزان مختلفة. وجود marker أو section منفرد لا يثبت packer؛ اجتماع أكثر من مؤشر يرفع الثقة. ستبقى النتيجة احتمالية، وسيعرض التقرير الأدلة ومصدرها داخل الملف بدل ادعاء كشف قطعي.
