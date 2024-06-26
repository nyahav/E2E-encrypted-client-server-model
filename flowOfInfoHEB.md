**הזרימה של המידע במודל קרברוס מותאם למשימה**

הזרימה של המידע במודל קרברוס מותאם למשימה מתבצעת בשלושה שלבים:

1. **רישום לקוח ושרת**
2. **קבלת מפתח סימטרי**
3. **שיגור הודעות**

**שלב 1: רישום לקוח ושרת**

בשלב זה, הלקוח והשרת נרשמים לשרת האימות. הלקוח שולח בקשת רישום, המכילה את שם המשתמש והסיסמה שלו. שרת האימות מאמת את הזהות של הלקוח, ושולח לו אישור הרשמה.

**בקשה: רישום לקוח**

```
קוד בקשה: 1025
שדה:
Name: שם המשתמש
Password: הסיסמה
```

**תשובה: רישום הצליח**

```
קוד תשובה: 1600
שדה:
Client ID: מזהה ייחודי של הלקוח
```

**שרת ההדפסה שולח גם בקשת רישום לשרת האימות, המכילה את שם המשתמש ומפתח סימטרי. שרת האימות מאמת את הזהות של השרת, ושולח לו אישור הרשמה.**

**בקשה: רישום שרת**

```
קוד בקשה: 1027
שדה:
Name: שם המשתמש
מפתח סימטרי: מפתח סימטרי של השרת ההדפסה
```

**תשובה: רישום הצליח**

```
קוד תשובה: 1600
שדה:
Client ID: מזהה ייחודי של השרת
```

**שלב 2: קבלת מפתח סימטרי**

לאחר שהלקוח והשרת נרשמים, הם יכולים לבקש מפתח סימטרי משרת האימות. הלקוח שולח בקשה למפתח סימטרי, המכילה את מזהה הלקוח ומזהה השרת ההדפסה. שרת האימות יוצר מפתח סימטרי חדש, ומצפין אותו בעזרת הסיסמה של הלקוח. המפתח הסימטרי המוצפן נשלח ללקוח.

**בקשה: בקשת מפתח סימטרי**

```
קוד בקשה: 1028
שדה:
Client ID: מזהה ייחודי של הלקוח
Server ID: מזהה ייחודי של השרת ההדפסה
```

**תשובה: שליחת מפתח סימטרי מוצפן**

```
קוד תשובה: 1603
שדה:
Client ID: מזהה ייחודי של הלקוח
מפתח סימטרי מוצפן: מפתח סימטרי מוצפן
Ticket: טיקט מוצפן
```

**הלקוח שולח את המפתח הסימטרי המוצפן ואת הטיקט המוצפן לשרת ההודעות. שרת ההודעות מפענח את המפתח הסימטרי המוצפן בעזרת הסיסמה של הלקוח, ומעביר את המפתח הסימטרי ללקוח.**

**בקשה: שליחת מפתח סימטרי לשרת הודעות**

```
שדה:
Authenticator: קוד זיהה של הלקוח
Ticket: טיקט מוצפן
```

**תשובה: מאשר קבלת מפתח סימטרי**

```
קוד תשובה: 1604
```

**שלב 3: שיגור הודעות**

לאחר שהלקוח מקבל את המפתח הסימטרי, הוא יכול לשלוח הודעות לשרת ההדפסה. ההודעות מוצפנות בעזרת המפתח הסימטרי.

**בקשה: שליחת הודעה**

```
שדה:
Message Size: גודל ההודעה (לאחר הצפנה)
IV: IV של הצפנה
Message Content: תוכן ההודעה
```

**תשובה: מאשר קבלת הודעה**

```
קוד תשובה: 1605
```

**כיצד מתבצעת ההצפנה?**

ההצפנה מתבצעת בעזרת אלגוריתם