using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace KatanWeb.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty] public int BlockSize { get; set; } = 32;

        // Sol panel: metin
        [BindProperty] public string PlainText { get; set; } = "";

        // Sağ panel: HEX
        [BindProperty] public string HexText { get; set; } = "";

        [BindProperty] public string Key { get; set; } = "";

        public string ErrorMessage { get; set; } = "";

        public void OnGet() { }

        public void OnPostEncrypt()
        {
            try
            {
                ErrorMessage = "";
                if (string.IsNullOrWhiteSpace(PlainText))
                {
                    ErrorMessage = "Şifrelenecek metin boş olamaz.";
                    return;
                }
                if (string.IsNullOrWhiteSpace(Key))
                {
                    ErrorMessage = "Anahtar boş olamaz.";
                    return;
                }

                var cipher = new KatanCipher(BlockSize);
                HexText = cipher.EncryptTextToHex(PlainText, Key);
            }
            catch (System.Exception ex)
            {
                ErrorMessage = ex.Message;
            }
        }

        public void OnPostDecrypt()
        {
            try
            {
                ErrorMessage = "";

                if (string.IsNullOrWhiteSpace(HexText))
                {
                    ErrorMessage = "Çözülecek HEX boş olamaz.";
                    return;
                }
                if (string.IsNullOrWhiteSpace(Key))
                {
                    ErrorMessage = "Anahtar boş olamaz.";
                    return;
                }

                // BlockSize UI'dan geliyor ama HEX prefix varsa zaten kontrol ediyor.
                var cipher = new KatanCipher(BlockSize);
                PlainText = cipher.DecryptHexToText(HexText, Key);
            }
            catch (Exception ex)
            {
                ErrorMessage = ex.Message;
            }
        }



    }
}
