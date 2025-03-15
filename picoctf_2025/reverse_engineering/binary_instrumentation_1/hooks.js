// example_v2.js

// 関数のアドレス (逆アセンブル結果から特定)
const FUN_1400014b0_ADDR = ptr("0x1400014b0"); // 例: 実際の値に置き換える
const FUN_1400018b0_ADDR = ptr("0x1400018b0");
const FUN_140001300_ADDR = ptr("0x140001300");
const FUN_140001dc0_ADDR = ptr("0x140001dc0");
const FUN_1400041c0_ADDR = ptr("0x1400041c0"); // 例: 実際の値に置き換える

const ENTRY_ADDR = ptr("0x140001000");  // 例：実際のアドレスに置き換える

// HeapAllocの戻り値（割り当てられたメモリのアドレス）を保持
let allocatedMemory = null;

// HeapAllocにフック
const HeapAllocAddr = Module.getExportByName(null, "HeapAlloc");
Interceptor.attach(HeapAllocAddr, {
  onLeave: function (retval) {
    allocatedMemory = retval;
    console.log("[+] HeapAlloc returned:", retval);
  }
});

// MessageBoxWにフック (もし文字列を表示するなら、内容を確認)
const MessageBoxWAddr = Module.getExportByName(null, "MessageBoxW");
if (MessageBoxWAddr != null) {
  Interceptor.attach(MessageBoxWAddr, {
    onEnter: function (args) {
      // args[1] がメッセージテキスト (LPWSTR)
      try {
        const message = args[1].readUtf16String();
        console.log("[+] MessageBoxW message:", message);
      } catch (error) {
        console.error("[-] Error reading MessageBoxW message:", error);
      }
    }
  });
}

// entry関数にフック (開始と終了を確認)
Interceptor.attach(ENTRY_ADDR, {
  onEnter: function (args) {
    console.log("[+] entry function called");
  },
  onLeave: function (retval) {
    console.log("[+] entry function returned:", retval);
  }
});


// FUN_1400014b0 にフック (詳細な解析)
Interceptor.attach(FUN_1400014b0_ADDR, {
  onEnter: function (args) {
    console.log("[+] FUN_1400014b0 called with arg:", args[0]);
    this.lVar6 = args[0]; // lVar6 をコンテキストに保存
    this.loopCount = 0; // ループカウンタを初期化
  },
  onLeave: function (retval) {
    console.log("[+] FUN_1400014b0 returned:", retval, "loopCount:", this.loopCount);
    if (retval.toInt32() == -0x60adf4d3) {
      console.warn("[!] FUN_1400014b0 returned -0x60adf4d3");
    }
  }
});

// FUN_1400018b0 にフック
Interceptor.attach(FUN_1400018b0_ADDR, {
  onEnter: function (args) {
    console.log("[+] FUN_1400018b0 called");
  },
  onLeave: function (retval) {
    console.log("[+] FUN_1400018b0 returned:", retval);
  }
});

// FUN_140001300 にフック (lVar8 のメモリを読み取る)
Interceptor.attach(FUN_140001300_ADDR, {
  onEnter: function (args) {
    console.log("[+] FUN_140001300 called with args:", args[0], args[1], args[2], args[3], args[4]);
    this.lVar8 = args[1]; // lVar8 をコンテキストに保存

  },
  onLeave: function (retval) {
    console.log("[+] FUN_140001300 returned:", retval);
    if (this.lVar8 != null && this.lVar8.toInt32() != 0) {
      try {
        // メモリの内容を読み取り (最初の32バイトを表示)
        const memContent = this.lVar8.readByteArray(32);
        console.log("[+] Memory content at lVar8:", memContent);

        // 文字列として読めそうなら読んでみる
        const str = this.lVar8.readUtf8String();
        if (str) {
          console.log("[+] String at lVar8: ", str);
        }
      } catch (error) {
        console.error("[-] Error reading memory at lVar8:", error);
      }
    }
  }
});

// FUN_140001dc0 にフック
Interceptor.attach(FUN_140001dc0_ADDR, {
  onEnter: function (args) {
    console.log("[+] FUN_140001dc0 called with args:", args[0], args[1], args[2]);
  },
  onLeave: function (retval) {
    console.log("[+] FUN_140001dc0 returned:", retval);
  }
});

// FUN_1400041c0 にフック (テーブル生成を確認)
Interceptor.attach(FUN_1400041c0_ADDR, {
  onEnter: function () {
    console.log("[+] FUN_1400041c0 (CRC table generation) called");
  },
  onLeave: function () {
    console.log("[+] FUN_1400041c0 finished");

    // DAT_1400070a0 のアドレスとサイズ
    const crcTableAddr = ptr("0x1400070a0"); // 例: 実際の値に置き換える
    const crcTableSize = 0x100 * 4; // 256 エントリ * 4 バイト (uint)

    // メモリ全体をスキャンして、CRCテーブルを探す
    console.log("[+] Scanning memory for CRC table...");
    Memory.scan(crcTableAddr, crcTableSize, "20 83 b8 ed", { //最初の値でスキャン。
      onMatch: function (address, size) {
        console.log("[+] Found potential CRC table usage at:", address);
        // 必要に応じて、ここからさらに詳細な解析を行う
        // 例: address の周辺のメモリを読み取る、逆参照する、など
      },
      onComplete: function () {
        console.log("[+] Memory scan complete.");
      }
    });
  }
});
