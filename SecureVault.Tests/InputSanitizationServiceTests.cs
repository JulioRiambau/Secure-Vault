using SecureVault.Services;
using Xunit;

namespace SecureVault.Tests;

public class InputSanitizationServiceTests
{
    private readonly InputSanitizationService _sanitizationService;
    private readonly ILogger<InputSanitizationService> _logger;

    public InputSanitizationServiceTests()
    {
        // Create a mock logger for testing
        _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<InputSanitizationService>();
        _sanitizationService = new InputSanitizationService(_logger);
    }

    [Fact]
    public void Sanitize_WithXSSPayload_RemovesScriptTags()
    {
        // Arrange
        string maliciousInput = "<img src=x onerror=\"alert('XSS')\">";

        // Act
        string result = _sanitizationService.Sanitize(maliciousInput);

        // Assert
        Assert.DoesNotContain("<", result); // Should be encoded
    }

    [Fact]
    public void Sanitize_WithScriptTag_EncodesIt()
    {
        // Arrange
        string maliciousInput = "<script>alert('XSS')</script>";

        // Act
        string result = _sanitizationService.Sanitize(maliciousInput);

        // Assert
        Assert.DoesNotContain("<script>", result);
        Assert.Contains("&lt;script&gt;", result);
    }

    [Fact]
    public void Sanitize_WithNormalInput_PreservesText()
    {
        // Arrange
        string normalInput = "GitHub Account";

        // Act
        string result = _sanitizationService.Sanitize(normalInput);

        // Assert
        Assert.Equal("GitHub Account", result);
    }

    [Fact]
    public void Sanitize_WithLeadingTrailingWhitespace_TrimsBoth()
    {
        // Arrange
        string inputWithWhitespace = "  Gmail  ";

        // Act
        string result = _sanitizationService.Sanitize(inputWithWhitespace);

        // Assert
        Assert.Equal("Gmail", result);
        Assert.False(result.StartsWith(" "));
        Assert.False(result.EndsWith(" "));
    }

    [Fact]
    public void IsValidInput_WithScriptTag_ReturnsFalse()
    {
        // Arrange
        string maliciousInput = "<script>alert('XSS')</script>";

        // Act
        bool result = _sanitizationService.IsValidInput(maliciousInput);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsValidInput_WithOnClickHandler_ReturnsFalse()
    {
        // Arrange
        string maliciousInput = "<button onclick=\"alert('XSS')\">Click me</button>";

        // Act
        bool result = _sanitizationService.IsValidInput(maliciousInput);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsValidInput_WithNormalText_ReturnsTrue()
    {
        // Arrange
        string normalInput = "AWS Console Password";

        // Act
        bool result = _sanitizationService.IsValidInput(normalInput);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsValidInput_WithJavaScriptProtocol_ReturnsFalse()
    {
        // Arrange
        string maliciousInput = "javascript:alert('XSS')";

        // Act
        bool result = _sanitizationService.IsValidInput(maliciousInput);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void SanitizeAndValidate_WithDangerousInput_ThrowsException()
    {
        // Arrange
        string maliciousInput = "<img src=x onerror=\"alert('XSS')\">";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _sanitizationService.SanitizeAndValidate(maliciousInput));
    }

    [Fact]
    public void SanitizeAndValidate_WithCleanInput_ReturnsSanitized()
    {
        // Arrange
        string cleanInput = "  Twitter Account  ";

        // Act
        string result = _sanitizationService.SanitizeAndValidate(cleanInput);

        // Assert
        Assert.Equal("Twitter Account", result);
    }

    [Fact]
    public void HtmlDecode_WithEncodedInput_DecodesCorrectly()
    {
        // Arrange
        string encodedInput = "&lt;test&gt;";

        // Act
        string result = _sanitizationService.HtmlDecode(encodedInput);

        // Assert
        Assert.Equal("<test>", result);
    }

    [Fact]
    public void Trim_WithWhitespaceOnly_ReturnsEmpty()
    {
        // Arrange
        string whitespaceOnly = "   ";

        // Act
        string result = _sanitizationService.Trim(whitespaceOnly);

        // Assert
        Assert.Empty(result);
    }
}
