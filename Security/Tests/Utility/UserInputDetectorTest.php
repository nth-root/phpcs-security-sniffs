<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Utility;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Config;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use const T_STRING;
use const T_VARIABLE;

class UserInputDetectorTest extends TestCase
{
    private UserInputDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new UserInputDetector();
    }

    #[DataProvider('getTaintedInputFiles')]
    public function testMarksSuperglobalsAsTainted(string $filename): void
    {
        $file = $this->createFile($filename);

        $position = $file->findNext(T_VARIABLE, 0, null, false, '$_GET');

        $this->assertTrue($this->detector->isTainted($file, $position));
    }

    public static function getTaintedInputFiles(): array
    {
        return [
            ['direct_input.php'],
            ['concatenated_input.php'],
        ];
    }

    public function testMarksTaintedVariablesAsTainted(): void
    {
        $file = $this->createFile('indirect_input.php');

        $position = $file->findNext(T_STRING, 0, null, false, 'shell_exec');
        $position = $file->findNext(T_VARIABLE, $position, null, false, '$target');

        $this->assertTrue($this->detector->isTainted($file, $position));
    }

    public function testDetectsDirectUserInput(): void
    {
        $file = $this->createFile('direct_input.php');

        $start = $file->findNext(T_STRING, 0, null, false, 'shell_exec');

        $this->assertTrue($this->detector->containsUserInput($file, $start));
    }

    public function testDetectsIndirectUserInput(): void
    {
        $file = $this->createFile('indirect_input.php');

        $start = $file->findNext(T_STRING, 0, null, false, 'shell_exec');

        $this->assertTrue($this->detector->containsUserInput($file, $start));
    }

    private function createFile(string $path): LocalFile
    {
        $config = new Config();

        $path = __DIR__ . '/fixtures/' . $path;

        $file = new LocalFile($path, new Ruleset($config), $config);
        $file->setContent(file_get_contents($path));
        $file->parse();

        return $file;
    }
}
