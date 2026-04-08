-- AlterTable
ALTER TABLE `bank_accounts` ADD COLUMN `openingBalance` DOUBLE NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE `salesperson_opening_balances` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `salespersonId` INTEGER NOT NULL,
    `partyType` ENUM('trader', 'company') NOT NULL,
    `partyId` INTEGER NOT NULL,
    `amount` DOUBLE NOT NULL DEFAULT 0,
    `notes` VARCHAR(191) NOT NULL DEFAULT '',
    `createdBy` INTEGER NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `salesperson_opening_balances_salespersonId_idx`(`salespersonId`),
    UNIQUE INDEX `salesperson_opening_balances_salespersonId_partyType_partyId_key`(`salespersonId`, `partyType`, `partyId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `bank_statements_bankAccountId_date_idx` ON `bank_statements`(`bankAccountId`, `date`);

-- CreateIndex
CREATE INDEX `bank_statements_sourceType_sourceId_idx` ON `bank_statements`(`sourceType`, `sourceId`);

-- AddForeignKey
ALTER TABLE `salesperson_opening_balances` ADD CONSTRAINT `salesperson_opening_balances_salespersonId_fkey` FOREIGN KEY (`salespersonId`) REFERENCES `users`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `salesperson_opening_balances` ADD CONSTRAINT `salesperson_opening_balances_createdBy_fkey` FOREIGN KEY (`createdBy`) REFERENCES `users`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
