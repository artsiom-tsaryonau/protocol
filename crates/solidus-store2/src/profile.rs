//! RocksDB tuning profiles. The live chain's conservative small-VPS
//! tuning becomes an explicit `Testnet` profile instead of the silent
//! default; `Mainnet` sizes for validator-class hardware.

use rocksdb::Options;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small-VPS friendly (the live testnet's bounded-growth tuning).
    Testnet,
    /// Validator-class: bigger memtables, more parallelism, bloom filters.
    Mainnet,
}

impl Profile {
    pub(crate) fn db_options(&self) -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_level_compaction_dynamic_level_bytes(true);
        match self {
            Profile::Testnet => {
                opts.set_max_total_wal_size(64 * 1024 * 1024);
                opts.set_keep_log_file_num(1);
                opts.set_recycle_log_file_num(0);
                opts.set_max_open_files(128);
                opts.set_write_buffer_size(8 * 1024 * 1024);
                opts.set_max_write_buffer_number(2);
                opts.set_target_file_size_base(8 * 1024 * 1024);
                opts.set_max_bytes_for_level_base(64 * 1024 * 1024);
            }
            Profile::Mainnet => {
                opts.set_max_total_wal_size(1024 * 1024 * 1024);
                opts.set_keep_log_file_num(4);
                opts.set_max_open_files(4096);
                opts.set_write_buffer_size(256 * 1024 * 1024);
                opts.set_max_write_buffer_number(4);
                opts.set_target_file_size_base(128 * 1024 * 1024);
                opts.set_max_bytes_for_level_base(1024 * 1024 * 1024);
                opts.increase_parallelism(num_cpus() as i32);
                opts.set_max_background_jobs(8);
            }
        }
        opts
    }

    /// Hot CFs: point-read heavy (account/DID lookups during execution).
    pub(crate) fn hot_cf_options(&self) -> Options {
        let mut opts = Options::default();
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        match self {
            Profile::Testnet => {
                opts.set_write_buffer_size(4 * 1024 * 1024);
                opts.set_target_file_size_base(8 * 1024 * 1024);
            }
            Profile::Mainnet => {
                opts.set_write_buffer_size(128 * 1024 * 1024);
                opts.set_target_file_size_base(64 * 1024 * 1024);
                let mut block = rocksdb::BlockBasedOptions::default();
                block.set_bloom_filter(10.0, false);
                opts.set_block_based_table_factory(&block);
            }
        }
        opts
    }

    /// Cold CFs: sequential bulk writes, range-pruned, rarely read.
    pub(crate) fn cold_cf_options(&self) -> Options {
        let mut opts = Options::default();
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        match self {
            Profile::Testnet => {
                opts.set_write_buffer_size(4 * 1024 * 1024);
            }
            Profile::Mainnet => {
                opts.set_write_buffer_size(64 * 1024 * 1024);
            }
        }
        opts
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
